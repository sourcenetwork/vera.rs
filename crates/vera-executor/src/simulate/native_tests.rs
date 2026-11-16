use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use vera_modules::acp::abi::IAcp;
use vera_modules::acp::types::{
    Object, PolicyCmd, PolicyCmdResult, PolicyCommandRequest, PolicyRecord,
};
use vera_modules::types::{BlockExecCtx, Timestamp};

use super::*;
use crate::ExecutionConfig;
use crate::dispatch::{ACP_ADDRESS, dispatch_to_module};
use crate::executor::native_dispatch::NATIVE_TX_GAS_LIMIT;
use crate::executor::native_outcome::NATIVE_REFUSAL_GAS;

const POLICY: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader\n";
const OWNER: &str = "did:key:owner";
const HEAD: Timestamp = Timestamp {
    seconds: 1_800_000_000,
    block_height: 41,
};

fn context() -> SimulationContext {
    SimulationContext::at_block(
        &ExecutionConfig::new(9001),
        30_000_000,
        HEAD.block_height,
        HEAD.seconds,
    )
}

fn command(policy: B256, command: PolicyCmd) -> Vec<u8> {
    IAcp::executePolicyCommandCall {
        policyId: policy,
        request: serde_json::to_vec(&PolicyCommandRequest {
            command,
            metadata: Default::default(),
        })
        .unwrap()
        .into(),
    }
    .abi_encode()
}

fn object(id: &str) -> Object {
    Object {
        resource: "file".into(),
        id: id.into(),
    }
}

/// Committed module values holding a policy whose `report` object `OWNER` registered.
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
    let mut write = |calldata: Vec<u8>, sequence| {
        let tx = TxExecCtx {
            signer: OWNER.into(),
            tx_hash: vec![1; 32],
            sequence,
        };
        let result = dispatch_to_module(
            &mut modules.acp,
            &mut modules.bulletin,
            &mut modules.vera,
            ACP_ADDRESS,
            &calldata,
            &block,
            &tx,
            crate::ExecutionConfig::new(9001).membership_limits(),
            1_000_000,
        )
        .unwrap()
        .unwrap();
        assert!(result.output.status.is_success());
        result.output.bytes
    };
    let created = write(
        IAcp::createPolicyCall {
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
            nonce: Default::default(),
        }
        .abi_encode(),
        0,
    );
    let record: PolicyRecord =
        PolicyRecord::from_json(&IAcp::createPolicyCall::abi_decode_returns(&created).unwrap())
            .unwrap();
    let policy = record.policy.id.as_str().parse().unwrap();
    write(
        command(policy, PolicyCmd::RegisterObject(object("report"))),
        1,
    );
    (modules, policy)
}

fn simulate(modules: &ModuleState, signer: &str, calldata: Vec<u8>) -> NativeSimulateResult {
    let request = NativeSimulateRequest::new(signer, ACP_ADDRESS, calldata.into()).unwrap();
    simulate_native_call(&context(), &request, modules).unwrap()
}

#[test]
fn a_write_succeeds_for_the_owner_is_refused_for_another_did_and_changes_nothing() {
    let (modules, policy) = committed();
    let before = modules.serialize_stores();
    let transfer = || {
        IAcp::transferObjectCall {
            policyId: policy,
            resource: "file".into(),
            objectId: "report".into(),
            newOwner: "did:key:next".into(),
        }
        .abi_encode()
    };

    let allowed = simulate(&modules, OWNER, transfer());
    assert!(allowed.success, "{:?}", allowed.refusal);
    assert_eq!(allowed.refusal, None);
    assert!(allowed.gas_used > 0 && allowed.gas_used < NATIVE_TX_GAS_LIMIT);
    assert!(!allowed.logs.is_empty());

    let refused = simulate(&modules, "did:key:other", transfer());
    assert!(!refused.success);
    let refusal = refused.refusal.unwrap();
    assert_eq!(refusal.module, vera_domain::RefusingModule::Acp);
    assert_eq!(refusal.kind, vera_domain::RefusalKind::Unauthorized);
    assert!(!refusal.message().is_empty());
    assert!(refused.gas_used >= NATIVE_REFUSAL_GAS && refused.gas_used < NATIVE_TX_GAS_LIMIT);
    assert!(refused.logs.is_empty() && refused.output.is_empty());

    assert_eq!(modules.serialize_stores(), before);
    assert_eq!(modules.nonces.get_nonce(OWNER).unwrap(), 0);
    let still_owned = simulate(&modules, OWNER, transfer());
    assert!(still_owned.success, "the first dry run moved the object");
}

#[test]
fn a_call_is_evaluated_at_the_height_and_time_of_its_context() {
    let (modules, policy) = committed();
    let register = command(policy, PolicyCmd::RegisterObject(object("draft")));
    let result = simulate(&modules, OWNER, register.clone());
    assert!(result.success, "{:?}", result.refusal);
    let bytes = IAcp::executePolicyCommandCall::abi_decode_returns(&result.output).unwrap();
    let PolicyCmdResult::RegisterObject { record } = serde_json::from_slice(&bytes).unwrap() else {
        panic!("a registration returns its record");
    };
    assert_eq!(record.metadata.creation_ts, HEAD);

    let request = NativeSimulateRequest::new(OWNER, ACP_ADDRESS, register.into()).unwrap();
    let epoch = SimulationContext {
        block_number: 0,
        timestamp: 0,
        ..context()
    };
    let at_epoch = simulate_native_call(&epoch, &request, &modules).unwrap();
    assert!(!at_epoch.success, "a write needs the block it would run in");
}

#[test]
fn calldata_no_module_can_read_is_a_refusal_with_its_reason() {
    let refused = simulate(&ModuleState::default(), OWNER, vec![1, 2, 3, 4]);
    assert!(!refused.success);
    let refusal = refused.refusal.unwrap();
    assert_eq!(refusal.kind, vera_domain::RefusalKind::UnknownSelector);
    assert_eq!(refused.gas_used, NATIVE_REFUSAL_GAS);
}

#[test]
fn a_request_outside_the_bounds_of_a_native_submission_is_not_built() {
    let run = |signer: &str, target, calldata: Vec<u8>| {
        NativeSimulateRequest::new(signer, target, calldata.into()).unwrap_err()
    };
    for signer in ["", "owner", "*"] {
        assert!(matches!(
            run(signer, ACP_ADDRESS, vec![]),
            NativeSimulateError::InvalidSigner(_)
        ));
    }
    let long = format!("did:key:{}", "z".repeat(MAX_SIMULATED_SIGNER_BYTES));
    assert!(matches!(
        run(&long, ACP_ADDRESS, vec![]),
        NativeSimulateError::InvalidSigner(_)
    ));
    assert!(matches!(
        run(OWNER, Address::repeat_byte(1), vec![]),
        NativeSimulateError::UnknownTarget(_)
    ));
    assert!(matches!(
        run(OWNER, ACP_ADDRESS, vec![0; vera_domain::MAX_TX_BYTES + 1]),
        NativeSimulateError::CalldataTooLarge { .. }
    ));
}

#[test]
fn a_key_named_in_another_spelling_acts_as_its_canonical_did() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let key = k256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let key = key.verifying_key();
    let canonical =
        vera_crypto::secp256k1::did_from_secp256k1_pubkey(key.to_encoded_point(true).as_bytes())
            .unwrap();
    let mut multicodec = vec![0xe7, 0x01];
    multicodec.extend_from_slice(key.to_encoded_point(false).as_bytes());
    let uncompressed = format!("did:key:u{}", URL_SAFE_NO_PAD.encode(multicodec));
    assert_ne!(uncompressed, canonical);
    let request = NativeSimulateRequest::new(&uncompressed, ACP_ADDRESS, Bytes::new()).unwrap();
    assert_eq!(request.signer, canonical);
}
