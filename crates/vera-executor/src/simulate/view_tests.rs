use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use vera_domain::{RefusalKind, RefusingModule};
use vera_modules::acp::abi::IAcp;
use vera_modules::acp::types::PolicyRecord;
use vera_modules::types::{BlockExecCtx, Timestamp};

use super::*;
use crate::ExecutionConfig;
use crate::dispatch::{ACP_ADDRESS, dispatch_to_module};

const POLICY: &str = "name: files\nresources:\n  - name: file\n";
const OWNER: &str = "did:key:owner";

fn context() -> SimulationContext {
    SimulationContext::at_block(&ExecutionConfig::new(9001), 30_000_000, 41, 1_800_000_000)
}

fn create_policy() -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: POLICY.as_bytes().to_vec().into(),
        marshalType: 1,
        nonce: Default::default(),
    }
    .abi_encode()
}

/// Committed module values holding one policy `OWNER` created.
fn committed() -> (ModuleState, B256) {
    let mut modules = ModuleState::default();
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 10,
            block_height: 1,
        },
        deployment_id: 9001,
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: OWNER.into(),
        tx_hash: vec![1; 32],
        sequence: 0,
    };
    let created = dispatch_to_module(
        &mut modules.acp,
        &mut modules.bulletin,
        &mut modules.vera,
        ACP_ADDRESS,
        &create_policy(),
        &block,
        &tx,
        crate::ExecutionConfig::new(9001).membership_limits(),
        1_000_000,
    )
    .unwrap()
    .unwrap();
    assert!(created.output.status.is_success());
    let record: PolicyRecord = serde_json::from_slice(
        &IAcp::createPolicyCall::abi_decode_returns(&created.output.bytes).unwrap(),
    )
    .unwrap();
    (modules, record.policy.id.as_str().parse().unwrap())
}

fn view(modules: &ModuleState, calldata: Vec<u8>) -> ViewCallResult {
    let call = ViewCall::new(ACP_ADDRESS, calldata.into()).unwrap();
    view_call(&context(), &call, modules).unwrap()
}

#[test]
fn a_view_returns_the_output_of_the_committed_values() {
    let (modules, policy) = committed();
    let result = view(
        &modules,
        IAcp::getPolicyCall { policyId: policy }.abi_encode(),
    );
    assert_eq!(result.refusal, None);
    let bytes = IAcp::getPolicyCall::abi_decode_returns(&result.output).unwrap();
    let record: PolicyRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record.policy.id.as_str().parse::<B256>().unwrap(), policy);
}

#[test]
fn a_write_is_refused_as_unauthenticated_and_writes_nothing() {
    let (modules, _) = committed();
    let before = modules.serialize_stores();
    let result = view(&modules, create_policy());
    let refusal = result.refusal.expect("a write needs a signer");
    assert_eq!(refusal.module, RefusingModule::Acp);
    assert_eq!(refusal.kind, RefusalKind::Unauthenticated);
    assert!(result.output.is_empty());
    assert_eq!(modules.serialize_stores(), before);
}

#[test]
fn calldata_no_module_can_read_is_a_refusal() {
    let result = view(&ModuleState::default(), vec![1, 2, 3, 4]);
    assert_eq!(result.refusal.unwrap().kind, RefusalKind::UnknownSelector);
}

#[test]
fn a_call_outside_the_bounds_of_a_native_submission_is_not_built() {
    assert!(matches!(
        ViewCall::new(Address::repeat_byte(1), Bytes::new()),
        Err(ViewCallError::UnknownTarget(_))
    ));
    assert!(matches!(
        ViewCall::new(ACP_ADDRESS, vec![0; vera_domain::MAX_TX_BYTES + 1].into()),
        Err(ViewCallError::CalldataTooLarge { .. })
    ));
}
