//! Module authority and failure reporting for calls made by contracts.

use super::{
    rollback::{
        CALL, CALLCODE, DELEGATECALL, STATICCALL, embedded_call, execute_with_executor,
        forwarding_code, install, requiring_code,
    },
    *,
};
use alloy_primitives::TxKind;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use vera_executor::{
    ModuleState, VeraExecutor,
    precompiles::{ACP_ADDRESS, BULLETIN_ADDRESS},
};
use vera_modules::{
    acp::{abi::IAcp, types::PolicyMarshalingType},
    bulletin::abi::IBulletin,
};

const CONTRACT: Address = Address::repeat_byte(0x22);

/// An executor whose ACP holds one policy owned by the transaction signer.
fn signer_policy() -> (VeraExecutor, B256) {
    let signer: PrivateKeySigner = "42".repeat(32).parse().unwrap();
    let owner = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        &signer.credential().verifying_key().to_sec1_bytes(),
    )
    .unwrap()
    .parse()
    .unwrap();
    let mut modules = ModuleState::default();
    let record = modules
        .acp
        .create_policy(
            &owner,
            "name: owned\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap();
    let executor = VeraExecutor::new(9001);
    executor.set_base_modules(modules);
    (executor, record.policy.id.parse().unwrap())
}

fn delete(policy: B256) -> Bytes {
    IAcp::deletePolicyCall { policyId: policy }
        .abi_encode()
        .into()
}

#[test]
fn the_signer_keeps_authority_over_its_own_call() {
    let (executor, policy) = signer_policy();
    let (outcome, modules) = execute_with_executor(
        &MockStateDb::new(),
        TxKind::Call(ACP_ADDRESS),
        delete(policy),
        executor,
    );
    assert!(outcome.receipts[0].success());
    assert!(modules.acp.query_policy_ids().unwrap().is_empty());
}

#[rstest]
#[case(CALL)]
#[case(CALLCODE)]
#[case(DELEGATECALL)]
#[case(STATICCALL)]
fn a_called_contract_cannot_use_the_signer_authority(#[case] opcode: u8) {
    let (executor, policy) = signer_policy();
    let state = MockStateDb::new();
    install(
        &state,
        CONTRACT,
        forwarding_code(ACP_ADDRESS, &[0x00], opcode),
    );
    let (outcome, modules) =
        execute_with_executor(&state, TxKind::Call(CONTRACT), delete(policy), executor);
    assert_eq!(outcome.executed_tx_indices, Some(vec![0]));
    assert!(outcome.receipts[0].success());
    assert!(outcome.receipts[0].logs().is_empty());
    assert_eq!(modules.acp.query_policy_ids().unwrap().len(), 1);
}

#[rstest]
#[case(CALL)]
#[case(CALLCODE)]
#[case(DELEGATECALL)]
fn initcode_cannot_use_the_signer_authority(#[case] opcode: u8) {
    let (executor, policy) = signer_policy();
    let (outcome, modules) = execute_with_executor(
        &MockStateDb::new(),
        TxKind::Create,
        embedded_call(&delete(policy), &[0x00], opcode),
        executor,
    );
    assert!(outcome.receipts[0].success());
    assert_eq!(modules.acp.query_policy_ids().unwrap().len(), 1);
}

fn signer_requiring_calls(policy: B256) -> Vec<(Address, Bytes)> {
    vec![
        (ACP_ADDRESS, delete(policy)),
        (
            ACP_ADDRESS,
            IAcp::editPolicyCall {
                policyId: policy,
                policy: Bytes::from_static(b"name: edited\nresources:\n  - name: file\n"),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
        ),
        (
            ACP_ADDRESS,
            IAcp::checkAccessCall {
                policyId: policy,
                resources: vec!["file".into()],
                objectIds: vec!["report".into()],
                permissions: vec!["read".into()],
                actor: "did:key:reader".into(),
            }
            .abi_encode()
            .into(),
        ),
        (
            BULLETIN_ADDRESS,
            IBulletin::createPostCall {
                namespace: "notes".into(),
                payload: Bytes::from_static(b"payload"),
                proof: Bytes::new(),
                artifact: String::new(),
            }
            .abi_encode()
            .into(),
        ),
    ]
}

#[test]
fn a_contract_call_without_a_signer_is_refused_and_included() {
    let (_, policy) = signer_policy();
    for (target, input) in signer_requiring_calls(policy) {
        let (executor, _) = signer_policy();
        let state = MockStateDb::new();
        install(&state, CONTRACT, requiring_code(target, CALL, None));
        let (outcome, modules) =
            execute_with_executor(&state, TxKind::Call(CONTRACT), input, executor);
        assert_eq!(outcome.executed_tx_indices, Some(vec![0]));
        assert_eq!(outcome.receipts.len(), 1);
        assert!(!outcome.receipts[0].success());
        assert_eq!(modules.acp.query_policy_ids().unwrap().len(), 1);
    }
}

#[rstest]
#[case(None, true)]
#[case(Some(500), false)]
fn a_module_call_that_exhausts_its_allowance_fails(
    #[case] allowance: Option<u16>,
    #[case] success: bool,
) {
    let (executor, _) = signer_policy();
    let state = MockStateDb::new();
    install(
        &state,
        CONTRACT,
        requiring_code(ACP_ADDRESS, STATICCALL, allowance),
    );
    let (outcome, _) = execute_with_executor(
        &state,
        TxKind::Call(CONTRACT),
        IAcp::getPoliciesCall {}.abi_encode().into(),
        executor,
    );
    assert_eq!(outcome.receipts.len(), 1);
    assert_eq!(outcome.receipts[0].success(), success);
}
