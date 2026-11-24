//! `vera_call` served in-process: answers, refusals, bounds and admission.

use alloy_primitives::{Address, B256, Bytes, U64, U256};
use vera_domain::{RefusalKind, RefusingModule, ViewCallResult};
use vera_executor::dispatch::ACP_ADDRESS;
use vera_modules::acp::types::PolicyRecord;

use super::simulation_tests::{
    HEAD_NUMBER, HEAD_TIME, POLICY, committed, local, provider, selector, word,
};
use crate::simulation_slots::{SIMULATION_SLOTS, SIMULATION_WAITERS};
use crate::{LocalRpcError, error::codes};

fn params(target: Address, calldata: Vec<u8>) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!(target),
        serde_json::json!(Bytes::from(calldata)),
    ]
}

fn get_policy(policy: B256) -> Vec<u8> {
    let mut calldata = selector("getPolicy(bytes32)");
    calldata.extend_from_slice(policy.as_slice());
    calldata
}

fn create_policy() -> Vec<u8> {
    let mut calldata = selector("createPolicy(bytes,uint8,bytes32)");
    calldata.extend_from_slice(&word(96));
    calldata.extend_from_slice(&word(1));
    calldata.extend_from_slice(&word(0));
    calldata.extend_from_slice(&word(POLICY.len()));
    calldata.extend_from_slice(POLICY.as_bytes());
    calldata.resize(calldata.len().next_multiple_of(32) + 4, 0);
    calldata
}

#[tokio::test]
async fn a_view_returns_the_output_at_the_head_revision() {
    let (modules, policy) = committed();
    let local = local(provider(modules));
    assert!(local.method_names().contains(&"vera_call"));

    let result: ViewCallResult = local
        .request("vera_call", params(ACP_ADDRESS, get_policy(policy)))
        .await
        .unwrap();
    assert_eq!(result.refusal, None);
    assert_eq!(result.block_number, U64::from(HEAD_NUMBER));
    assert_eq!(result.timestamp, U64::from(HEAD_TIME));
    let length = U256::from_be_slice(&result.output[32..64]).to::<usize>();
    let record: PolicyRecord = serde_json::from_slice(&result.output[64..64 + length]).unwrap();
    assert_eq!(record.policy.id.parse::<B256>().unwrap(), policy);
}

#[tokio::test]
async fn a_write_is_refused_as_unauthenticated_and_writes_nothing() {
    let (modules, _) = committed();
    let before = modules.read().unwrap().serialize_stores();
    let local = local(provider(modules.clone()));

    let result: ViewCallResult = local
        .request("vera_call", params(ACP_ADDRESS, create_policy()))
        .await
        .unwrap();
    let refusal = result.refusal.expect("a write needs a signer");
    assert_eq!(refusal.module, RefusingModule::Acp);
    assert_eq!(refusal.kind, RefusalKind::Unauthenticated);
    assert!(result.output.is_empty());
    assert_eq!(modules.read().unwrap().serialize_stores(), before);
}

#[tokio::test]
async fn a_call_outside_submission_bounds_is_invalid_params() {
    let (modules, policy) = committed();
    let local = local(provider(modules));
    for params in [
        params(Address::repeat_byte(1), get_policy(policy)),
        params(ACP_ADDRESS, vec![0; vera_domain::MAX_TX_BYTES + 1]),
    ] {
        let error = local
            .request::<ViewCallResult>("vera_call", params)
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
async fn a_call_beyond_the_shared_slots_is_refused_as_retryable() {
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
        local.request::<ViewCallResult>("vera_call", params(ACP_ADDRESS, get_policy(policy))),
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
    let admitted: ViewCallResult = local
        .request("vera_call", params(ACP_ADDRESS, get_policy(policy)))
        .await
        .unwrap();
    assert_eq!(admitted.refusal, None);
}
