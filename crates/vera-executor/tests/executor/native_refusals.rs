use super::*;
use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use vera_domain::{ExecutionReceipt, RefusalKind, RefusingModule, receipt_commitment};
use vera_executor::{
    SimulateRequest, SimulationContext, VeraExecutor,
    precompiles::{ACP_ADDRESS, BULLETIN_ADDRESS, VALIDATOR_REGISTRY_ADDRESS, VERA_ADDRESS},
    simulate_call,
};
use vera_modules::acp::abi::IAcp;
use vera_modules::bulletin::abi::IBulletin;
use vera_modules::validator_registry::abi::IValidatorRegistry;
use vera_modules::vera::abi::IVera;

const NATIVE_LIMIT: u64 = 1_000_000;
const REFUSAL_MINIMUM: u64 = 5_000;

fn native(target: Address, calldata: Vec<u8>) -> Bytes {
    let key = ark_bls12_381::Fr::from(11u64);
    let public = (ark_bls12_381::G1Affine::generator() * key).into_affine();
    let mut encoded = Vec::new();
    public.serialize_compressed(&mut encoded).unwrap();
    let mut request = vera_domain::NativeTx {
        chain_id: 9001,
        nonce: 0,
        bls_pubkey: FixedBytes::from_slice(&encoded),
        target,
        calldata: calldata.into(),
        signature: Default::default(),
    };
    request.signature =
        FixedBytes::from_slice(&vera_crypto::bls::sign(&key, &request.signing_data()).unwrap());
    request.encode_wire().into()
}

fn execute(target: Address, calldata: Vec<u8>) -> ExecutionReceipt {
    let executor = VeraExecutor::new(9001);
    let context = BlockContext::new(
        Header {
            number: 1,
            timestamp: 100,
            gas_limit: NATIVE_LIMIT,
            ..Default::default()
        },
        B256::ZERO,
    );
    let (mut outcome, _) = executor
        .execute_with_modules(
            &MockStateDb::new(),
            &context,
            &[native(target, calldata)],
            executor.snapshot(),
        )
        .unwrap();
    assert_eq!(outcome.executed_tx_indices, Some(vec![0]));
    outcome.receipts.pop().unwrap()
}

fn assert_refused(
    receipt: &ExecutionReceipt,
    module: RefusingModule,
    kind: RefusalKind,
    message: &str,
) {
    assert!(!receipt.success());
    assert!(receipt.logs().is_empty());
    let refusal = receipt
        .refusal
        .as_ref()
        .expect("a refused request names its refusal");
    assert_eq!((refusal.module, refusal.kind), (module, kind), "{refusal}");
    assert!(
        refusal.message().contains(message),
        "{:?} lacks {message:?}",
        refusal.message()
    );
}

fn policy(definition: &str) -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: definition.as_bytes().to_vec().into(),
        marshalType: 2,
        nonce: Default::default(),
    }
    .abi_encode()
}

#[test]
fn a_policy_the_parser_refuses_is_named_in_the_receipt_and_charged_what_it_used() {
    // The current parser accepts a permission with no expression, so the
    // nearest refusal is an expression naming a relation the resource lacks.
    let accepted = execute(
        ACP_ADDRESS,
        policy(
            r#"{"name":"registrations","resources":[{"name":"file","permissions":[{"name":"read"}]}]}"#,
        ),
    );
    assert!(accepted.success(), "{:?}", accepted.refusal);
    assert_eq!(accepted.refusal, None);

    let refused = execute(
        ACP_ADDRESS,
        policy(
            r#"{"name":"registrations","resources":[{"name":"file","permissions":[{"name":"read","expr":"reader"}]}]}"#,
        ),
    );
    assert_refused(
        &refused,
        RefusingModule::Acp,
        RefusalKind::InvalidPolicy,
        "invalid policy",
    );
    assert!((REFUSAL_MINIMUM..NATIVE_LIMIT).contains(&refused.gas_used));
    assert_eq!(refused.cumulative_gas_used(), refused.gas_used);
}

#[test]
fn each_module_names_its_refusal() {
    assert_refused(
        &execute(ACP_ADDRESS, vec![0xde, 0xad, 0xbe, 0xef]),
        RefusingModule::Acp,
        RefusalKind::UnknownSelector,
        "unknown ACP selector: 0xdeadbeef",
    );
    assert_refused(
        &execute(ACP_ADDRESS, IAcp::createPolicyCall::SELECTOR.to_vec()),
        RefusingModule::Acp,
        RefusalKind::UndecodableInput,
        "ABI",
    );
    assert_refused(
        &execute(
            BULLETIN_ADDRESS,
            IBulletin::registerNamespaceCall {
                namespace: String::new(),
            }
            .abi_encode(),
        ),
        RefusingModule::Bulletin,
        RefusalKind::InvalidArgument,
        "namespace must be nonempty",
    );
    assert_refused(
        &execute(
            VERA_ADDRESS,
            IVera::invalidateJWSCall {
                tokenHash: "missing".into(),
            }
            .abi_encode(),
        ),
        RefusingModule::Vera,
        RefusalKind::NotFound,
        "JWS token not found: missing",
    );
    assert_refused(
        &execute(
            VALIDATOR_REGISTRY_ADDRESS,
            IValidatorRegistry::setPolicyCall {
                policyId: B256::repeat_byte(1),
            }
            .abi_encode(),
        ),
        RefusingModule::ValidatorRegistry,
        RefusalKind::Unauthorized,
        "unauthorized",
    );
}

#[test]
fn every_refusal_on_caller_input_is_charged_at_least_the_minimum_and_less_than_the_limit() {
    for receipt in [
        execute(ACP_ADDRESS, vec![0xde, 0xad, 0xbe, 0xef]),
        execute(
            VERA_ADDRESS,
            IVera::invalidateJWSCall {
                tokenHash: "missing".into(),
            }
            .abi_encode(),
        ),
    ] {
        assert_eq!(receipt.gas_used, REFUSAL_MINIMUM, "{:?}", receipt.refusal);
    }
}

#[test]
fn an_exhausted_allowance_keeps_its_own_kind_and_the_full_charge() {
    let request = format!("{{\"policy\":\"{}\"}}", "x".repeat(2_200_000));
    let exhausted = execute(
        ACP_ADDRESS,
        IAcp::createPolicyWithOptionsCall {
            request: request.into_bytes().into(),
        }
        .abi_encode(),
    );
    assert_refused(
        &exhausted,
        RefusingModule::Acp,
        RefusalKind::OutOfGas,
        "out of gas",
    );
    assert_eq!(exhausted.gas_used, NATIVE_LIMIT);

    let refused = execute(
        ACP_ADDRESS,
        policy(
            r#"{"name":"x","resources":[{"name":"file","permissions":[{"name":"read","expr":"reader"}]}]}"#,
        ),
    );
    assert!(refused.gas_used < exhausted.gas_used);
    assert_ne!(
        receipt_commitment(NATIVE_LIMIT, std::slice::from_ref(&exhausted)),
        receipt_commitment(NATIVE_LIMIT, &[exhausted.with_refusal(refused.refusal)]),
    );
}

#[test]
fn a_contract_caller_still_receives_the_refusal_message_as_revert_data() {
    let context = SimulationContext::at_block(
        &vera_executor::ExecutionConfig::new(9001),
        30_000_000,
        1,
        100,
    );
    let modules = vera_executor::ModuleState::default();
    let call = |data: Vec<u8>| {
        simulate_call(
            &MockStateDb::new(),
            &context,
            &SimulateRequest {
                from: Address::repeat_byte(0x44),
                to: Some(ACP_ADDRESS),
                value: U256::ZERO,
                data: data.into(),
                gas: Some(NATIVE_LIMIT),
            },
            Some(&modules),
        )
        .unwrap()
    };

    let commitment = IAcp::getRegistrationsCommitmentCall { commitmentId: 42 }.abi_encode();
    let reverted = call(commitment.clone());
    assert!(!reverted.success);
    let native = execute(ACP_ADDRESS, commitment);
    let refusal = native.refusal.unwrap();
    assert_eq!(refusal.kind, RefusalKind::NotFound);
    assert_eq!(reverted.output.as_ref(), refusal.message().as_bytes());

    // A refusal raised as an error reaches the contract without its kind tag.
    let unsigned = call(policy(r#"{"name":"x"}"#));
    assert!(!unsigned.success);
    assert_eq!(
        unsigned.output.as_ref(),
        b"fatal: module call requires an authenticated caller"
    );
}
