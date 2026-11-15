use std::sync::{Arc, RwLock};

use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U64, U256, keccak256};
use vera_domain::NativeCallSimulation;
use vera_executor::{ExecutionConfig, ModuleState, SharedModuleState, SpecId};
use vera_indexer::{BlockIndex, IndexedBlock};
use vera_modules::acp::types::PolicyRecord;
use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};
use vera_traits::{StateDbError, StateDbRead};

use super::IndexedStateProvider;
use crate::simulation_slots::{SIMULATION_SLOTS, SIMULATION_WAITERS};
use crate::state_provider::StateProvider;
use crate::types::CallRequest;
use crate::{LocalRpc, LocalRpcError, NodeState, RpcServer, error::codes};

const CHAIN: u64 = 9001;
const HEAD_NUMBER: u64 = 7;
const HEAD_TIME: u64 = 1_800_000_123;
const OWNER: &str = "did:key:owner";
const POLICY: &str = "name: files\nresources:\n  - name: file\n";

#[derive(Clone)]
struct EmptyState;

impl StateDbRead for EmptyState {
    async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
        Ok(0)
    }
    async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
        Ok(U256::ZERO)
    }
    async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
        Ok(KECCAK256_EMPTY)
    }
    async fn code(&self, _code_hash: &B256) -> Result<Bytes, StateDbError> {
        Ok(Bytes::new())
    }
    async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
        Ok(U256::ZERO)
    }
}

fn provider(modules: SharedModuleState) -> IndexedStateProvider<EmptyState> {
    let index = Arc::new(BlockIndex::new());
    index.insert_block(
        IndexedBlock {
            hash: B256::repeat_byte(7),
            number: HEAD_NUMBER,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp: HEAD_TIME,
            gas_limit: 30_000_000,
            gas_used: 0,
            base_fee_per_gas: None,
            prevrandao: B256::ZERO,
            transaction_hashes: vec![],
        },
        vec![],
        vec![],
    );
    IndexedStateProvider::new(
        index,
        EmptyState,
        CHAIN,
        SpecId::CANCUN,
        30_000_000,
        modules,
    )
    .with_execution_config(ExecutionConfig::new(CHAIN))
}

fn local(provider: IndexedStateProvider<EmptyState>) -> LocalRpc {
    RpcServer::with_state_provider(
        NodeState::new(CHAIN, 0, 1),
        "127.0.0.1:0".parse().unwrap(),
        CHAIN,
        provider,
    )
    .into_local()
    .unwrap()
}

fn selector(signature: &str) -> Vec<u8> {
    keccak256(signature)[..4].to_vec()
}

fn word(value: usize) -> [u8; 32] {
    U256::from(value).to_be_bytes()
}

/// Committed module values holding one policy `OWNER` created, and its identifier.
fn committed() -> (SharedModuleState, B256) {
    let mut modules = ModuleState::default();
    let mut calldata = selector("createPolicy(bytes,uint8)");
    calldata.extend_from_slice(&word(64));
    calldata.extend_from_slice(&word(1));
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
        1_000_000,
    )
    .unwrap()
    .unwrap();
    assert!(created.precompile.status.is_success());
    let returned = &created.precompile.bytes;
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
async fn eth_call_and_estimate_observe_the_head_height_and_time() {
    let provider = provider(Arc::default());
    const NUMBER: u8 = 0x43;
    const TIMESTAMP: u8 = 0x42;
    for (opcode, expected) in [(NUMBER, HEAD_NUMBER), (TIMESTAMP, HEAD_TIME)] {
        // Initcode whose deployed code is the word the opcode pushes.
        let request = CallRequest {
            input: Some(Bytes::from(vec![
                opcode, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3,
            ])),
            ..Default::default()
        };
        let output = provider.call(request.clone(), None).await.unwrap();
        assert_eq!(U256::from_be_slice(&output), U256::from(expected));
        assert!(provider.estimate_gas(request, None).await.unwrap() >= 21_000);
    }
}

#[tokio::test]
async fn a_native_write_is_simulated_for_its_owner_refused_for_another_did_and_writes_nothing() {
    let (modules, policy) = committed();
    let root = modules.read().unwrap().state_root();
    let local = local(provider(modules.clone()));
    assert!(local.method_names().contains(&"vera_simulateNativeCall"));

    let allowed: NativeCallSimulation = local
        .request("vera_simulateNativeCall", delete_policy(OWNER, policy))
        .await
        .unwrap();
    assert!(allowed.success, "{:?}", allowed.reason);
    assert_eq!(allowed.reason, None);
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
    assert!(refused.reason.unwrap().contains("only the policy creator"));
    assert!(refused.logs.is_empty() && refused.output.is_empty());

    let after = modules.read().unwrap();
    assert_eq!(after.state_root(), root);
    assert_eq!(after.nonces.get_nonce(OWNER).unwrap(), 0);
    assert!(after.acp.query_policy(&hex::encode(policy)).is_ok());
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
