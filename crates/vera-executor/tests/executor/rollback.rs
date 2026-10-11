use super::*;
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{TxKind, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use vera_executor::{
    ExecutionOutcome, ModuleState, VeraExecutor,
    precompiles::{ACP_ADDRESS, VALIDATOR_REGISTRY_ADDRESS},
};
use vera_modules::{acp::abi::IAcp, validator_registry::abi::IValidatorRegistry};

fn policy(name: &str) -> Bytes {
    IAcp::createPolicyCall {
        policy: format!("name: {name}\nresources:\n  - name: file\n")
            .into_bytes()
            .into(),
        marshalType: 1,
    }
    .abi_encode()
    .into()
}

fn forwarding_code(target: Address, end: &[u8], is_static: bool) -> Bytes {
    // Copy calldata, call the target, and discard the success flag.
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f];
    if !is_static {
        code.push(0x5f);
    }
    code.push(0x73);
    code.extend_from_slice(target.as_slice());
    code.extend_from_slice(&[0x5a, if is_static { 0xfa } else { 0xf1 }, 0x50]);
    code.extend_from_slice(end);
    code.into()
}

fn embedded_call(data: &[u8], end: &[u8]) -> Bytes {
    let length = u16::try_from(data.len()).unwrap().to_be_bytes();
    // CODECOPY the appended input, then call ACP. This also works in initcode.
    let mut code = vec![
        0x61, length[0], length[1], 0x61, 0, 0, 0x5f, 0x39, 0x5f, 0x5f, 0x61, length[0], length[1],
        0x5f, 0x5f, 0x73,
    ];
    code.extend_from_slice(ACP_ADDRESS.as_slice());
    code.extend_from_slice(&[0x5a, 0xf1, 0x50]);
    code.extend_from_slice(end);
    let offset = u16::try_from(code.len()).unwrap().to_be_bytes();
    code[4..6].copy_from_slice(&offset);
    code.extend_from_slice(data);
    code.into()
}

fn install(state: &MockStateDb, address: Address, code: Bytes) {
    let code_hash = keccak256(&code);
    state.insert_code(code_hash, code);
    state.insert_account(
        address,
        MockAccount {
            code_hash,
            ..Default::default()
        },
    );
}

fn execute(state: &MockStateDb, to: TxKind, input: Bytes) -> (ExecutionOutcome, ModuleState) {
    execute_with_executor(state, to, input, VeraExecutor::new(9001))
}

pub(super) fn execute_with_executor(
    state: &MockStateDb,
    to: TxKind,
    input: Bytes,
    executor: VeraExecutor,
) -> (ExecutionOutcome, ModuleState) {
    let signer: PrivateKeySigner = "42".repeat(32).parse().unwrap();
    state.insert_account(
        signer.address(),
        MockAccount {
            balance: U256::from(10).pow(U256::from(18)),
            ..Default::default()
        },
    );
    let tx = TxLegacy {
        chain_id: Some(9001),
        gas_limit: 1_000_000,
        to,
        input,
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let wire = TxEnvelope::Legacy(tx.into_signed(signature))
        .encoded_2718()
        .into();
    let context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    let (outcome, modules) = executor
        .execute_with_modules(state, &context, &[wire], executor.snapshot())
        .unwrap();
    executor.publish_snapshot(modules);
    let modules = executor.modules().read().unwrap().clone();
    (outcome, modules)
}

#[rstest]
#[case(&[0x00], &[0x00], false, true, 0)]
#[case(&[0x00], &[0x5f, 0x5f, 0xfd], false, false, 0)]
#[case(&[0x5f, 0x5f, 0xfd], &[0x00], false, true, 0)]
#[case(&[0xfe], &[0x00], false, true, 0)]
#[case(&[0x00], &[0x00], true, true, 0)]
fn nested_calls_cannot_inherit_signer_authority(
    #[case] inner_end: &[u8],
    #[case] outer_end: &[u8],
    #[case] is_static: bool,
    #[case] success: bool,
    #[case] policies: usize,
) {
    let state = MockStateDb::new();
    let inner = Address::repeat_byte(0x11);
    let outer = Address::repeat_byte(0x22);
    install(
        &state,
        inner,
        forwarding_code(ACP_ADDRESS, inner_end, is_static),
    );
    install(&state, outer, forwarding_code(inner, outer_end, false));
    let (outcome, modules) = execute(&state, TxKind::Call(outer), policy("rollback"));
    assert_eq!(outcome.receipts.len(), 1);
    assert_eq!(outcome.receipts[0].success(), success);
    assert_eq!(modules.acp.query_policy_ids().unwrap().len(), policies);
    assert_eq!(outcome.receipts[0].logs().len(), policies);
}

#[rstest]
#[case(&[0x00], true)]
#[case(&[0x5f, 0x5f, 0xfd], false)]
fn creation_cannot_inherit_signer_authority(#[case] end: &[u8], #[case] success: bool) {
    let (outcome, modules) = execute(
        &MockStateDb::new(),
        TxKind::Create,
        embedded_call(&policy("constructor"), end),
    );
    assert_eq!(outcome.receipts[0].success(), success);
    assert!(modules.acp.query_policy_ids().unwrap().is_empty());
}

#[test]
fn post_execution_error_restores_successful_module_call() {
    // The beneficiary is loaded when execution has finished, to credit its fee.
    let state = MockStateDb {
        unreadable_account: Some(Address::ZERO),
        ..Default::default()
    };
    let (outcome, modules) = execute(&state, TxKind::Call(ACP_ADDRESS), policy("discarded"));
    assert!(outcome.receipts.is_empty());
    assert_eq!(outcome.executed_tx_indices, Some(vec![]));
    assert!(modules.acp.query_policy_ids().unwrap().is_empty());
}

#[rstest]
#[case(false)]
#[case(true)]
fn registry_static_calls_allow_only_queries(#[case] query: bool) {
    let state = MockStateDb::new();
    let outer = Address::repeat_byte(0x22);
    let mut code = forwarding_code(VALIDATOR_REGISTRY_ADDRESS, &[], true).to_vec();
    code.pop();
    let success = u8::try_from(code.len() + 6).unwrap();
    code.extend_from_slice(&[0x60, success, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x00]);
    install(&state, outer, code.into());
    let input = if query {
        IValidatorRegistry::getActiveValidatorCountCall {}.abi_encode()
    } else {
        IValidatorRegistry::setPolicyCall {
            policyId: B256::repeat_byte(7),
        }
        .abi_encode()
    };
    let (outcome, _) = execute(&state, TxKind::Call(outer), input.into());
    assert_eq!(outcome.receipts[0].success(), query);
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.values().all(U256::is_zero))
    );
}

#[test]
fn unconfigured_membership_policy_cannot_be_claimed() {
    let call = IValidatorRegistry::setPolicyCall {
        policyId: B256::repeat_byte(7),
    };
    let (outcome, _) = execute(
        &MockStateDb::new(),
        TxKind::Call(VALIDATOR_REGISTRY_ADDRESS),
        call.abi_encode().into(),
    );
    assert!(!outcome.receipts[0].success());
    assert!(
        outcome
            .changes
            .accounts
            .get(&VALIDATOR_REGISTRY_ADDRESS)
            .is_none_or(|account| account.storage.values().all(U256::is_zero))
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn administrative_state_follows_outer_call_result(#[case] revert: bool) {
    use vera_modules::{
        acp::types::AcpParams,
        vera::{abi::IVera, administration::*},
    };
    let key: PrivateKeySigner = "01".repeat(32).parse().unwrap();
    let mut modules = ModuleState::default();
    modules
        .vera
        .initialize_administration(OperatorPolicy {
            threshold: 1,
            keys: vec![hex::encode(
                key.credential().verifying_key().to_sec1_bytes(),
            )],
        })
        .unwrap();
    let before = (
        modules.vera.store().serialize(),
        modules.acp.store().serialize(),
    );
    let request = AdministrativeRequest {
        genesis_id: [7; 32],
        sequence: 0,
        expires_at: 100,
        command: AdministrativeCommand::SetAcpParameters(AcpParams {
            policy_command_max_expiration_delta: 42,
            ..Default::default()
        }),
    };
    let signature = key
        .sign_hash_sync(&B256::from(request.signing_digest().unwrap()))
        .unwrap();
    let signed = SignedAdministrativeRequest {
        request,
        approvals: vec![OperatorApproval {
            signer: 0,
            signature: hex::encode(&signature.as_bytes()[..64]),
        }],
    };
    let input = IVera::applyAdministrationCall {
        request: serde_json::to_vec(&signed).unwrap().into(),
    }
    .abi_encode();
    let executor = VeraExecutor::new(9001).with_genesis_id([7; 32]);
    executor.set_base_modules(modules);
    let state = MockStateDb::new();
    let outer = Address::repeat_byte(0x11);
    let end: &[u8] = if revert { &[0x5f, 0x5f, 0xfd] } else { &[0x00] };
    install(
        &state,
        outer,
        forwarding_code(vera_executor::precompiles::VERA_ADDRESS, end, false),
    );
    let (outcome, modules) =
        execute_with_executor(&state, TxKind::Call(outer), input.into(), executor);
    assert_eq!(outcome.receipts[0].success(), !revert);
    if revert {
        assert_eq!(
            (
                modules.vera.store().serialize(),
                modules.acp.store().serialize()
            ),
            before
        );
    } else {
        assert_eq!(modules.vera.administration().unwrap().unwrap().sequence, 1);
        assert_eq!(
            modules
                .acp
                .query_params()
                .unwrap()
                .policy_command_max_expiration_delta,
            42
        );
    }
}
