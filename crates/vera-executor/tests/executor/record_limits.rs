use super::*;
use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use vera_executor::{
    ExecutionConfig, MempoolValidator, ModuleSnapshot, ModuleState, VeraExecutor,
    precompiles::ACP_ADDRESS,
};
use vera_modules::{
    acp::{
        abi::IAcp,
        keys,
        types::{Object, PolicyMarshalingType},
    },
    kv_store::{NATIVE_MAX_KEY_BYTES, NATIVE_MAX_VALUE_BYTES},
};

const NATIVE_LIMIT: u64 = 1_000_000;

fn fixture() -> (VeraExecutor, B256) {
    let mut modules = ModuleState::default();
    let record = modules
        .acp
        .create_policy(
            &"did:key:owner".parse().unwrap(),
            "name: bounds\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    let policy = record.policy.id.parse().unwrap();
    let executor = VeraExecutor::new(9001);
    executor.set_base_modules(modules);
    (executor, policy)
}

fn register(policy: B256, object: &str) -> Vec<u8> {
    IAcp::registerObjectCall {
        policyId: policy,
        resource: "file".into(),
        objectId: object.into(),
    }
    .abi_encode()
}

fn oversized_object(policy: B256) -> String {
    let object = "x".repeat(32768);
    let prefix = keys::relationship_storage_prefix(
        &hex::encode(policy),
        &keys::object_prefix("file", &object),
    );
    // Even the prefix exceeds the backend limit, before the relation and subject suffix.
    assert!(prefix.len() > NATIVE_MAX_KEY_BYTES);
    object
}

fn native(nonce: u64, calldata: Vec<u8>) -> (Bytes, String) {
    let key = ark_bls12_381::Fr::from(7u64);
    let public = (ark_bls12_381::G1Affine::generator() * key).into_affine();
    let mut encoded = Vec::new();
    public.serialize_compressed(&mut encoded).unwrap();
    let mut request = vera_domain::NativeTx {
        chain_id: 9001,
        nonce,
        bls_pubkey: FixedBytes::from_slice(&encoded),
        target: ACP_ADDRESS,
        calldata: calldata.into(),
        signature: Default::default(),
    };
    request.signature =
        FixedBytes::from_slice(&vera_crypto::bls::sign(&key, &request.signing_data()).unwrap());
    (
        request.encode_wire().into(),
        vera_crypto::bls::did_from_bls_pubkey(&public).unwrap(),
    )
}

fn module_state(snapshot: &ModuleSnapshot) -> ModuleState {
    let view = VeraExecutor::new(9001);
    view.commit_snapshot(1, snapshot.clone()).unwrap();
    view.modules().read().unwrap().clone()
}

fn context() -> BlockContext {
    BlockContext::new(
        Header {
            number: 1,
            timestamp: 100,
            gas_limit: 2 * NATIVE_LIMIT,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    )
}

#[rstest]
#[case(false)]
#[case(true)]
fn oversized_native_registration_rolls_back_and_allows_next_nonce(#[case] batch: bool) {
    let (executor, policy) = fixture();
    let parent = executor.snapshot().unwrap();
    let before = module_state(&parent).serialize_stores();
    let object = oversized_object(policy);
    let oversized = register(policy, &object);
    let input = if batch {
        IAcp::batchCallsCall {
            calls: vec![register(policy, "rolled-back").into(), oversized.into()],
        }
        .abi_encode()
    } else {
        oversized
    };
    let (failed, actor) = native(0, input);
    let (healthy, _) = native(1, register(policy, "healthy"));
    let state = MockStateDb::new();
    let mut validator =
        MempoolValidator::new(state.clone(), ExecutionConfig::new(9001), 0).with_native_only(true);
    for tx in [&failed, &healthy] {
        assert!(tx.len() < vera_domain::MAX_TX_BYTES);
        let checked = MempoolValidator::<MockStateDb>::pre_validate_native(9001, tx).unwrap();
        validator.admit_native(&checked).unwrap();
    }

    let (failure, failed_modules) = executor
        .execute_with_modules(
            &state,
            &context(),
            std::slice::from_ref(&failed),
            parent.clone(),
        )
        .unwrap();
    assert_eq!(failure.executed_tx_indices, Some(vec![0]));
    assert_eq!(failure.receipts.len(), 1);
    assert!(!failure.receipts[0].success());
    assert_eq!(failure.gas_used, NATIVE_LIMIT);
    assert_eq!(failure.receipts[0].cumulative_gas_used(), NATIVE_LIMIT);
    assert!(failure.receipts[0].logs().is_empty());
    let restored = module_state(&failed_modules);
    assert_eq!(&restored.serialize_stores()[..3], &before[..3]);
    assert_eq!(restored.nonces.get_nonce(&actor).unwrap(), 1);
    assert!(
        failed_modules.changes_from(&parent)[..3]
            .iter()
            .all(Vec::is_empty)
    );

    let txs = [failed, healthy];
    let (outcome, next) = executor
        .execute_with_modules(&state, &context(), &txs, parent.clone())
        .unwrap();
    assert_eq!(outcome.executed_tx_indices, Some(vec![0, 1]));
    assert_eq!(outcome.receipts.len(), 2);
    assert!(!outcome.receipts[0].success());
    assert!(outcome.receipts[0].logs().is_empty());
    assert!(outcome.receipts[1].success());
    assert_eq!(outcome.receipts[1].logs().len(), 1);
    assert_eq!(outcome.gas_used, NATIVE_LIMIT + 5000);
    let modules = module_state(&next);
    assert_eq!(modules.nonces.get_nonce(&actor).unwrap(), 2);
    for id in [object.as_str(), "rolled-back", "healthy"] {
        let (registered, _) = modules
            .acp
            .query_object_owner(
                &hex::encode(policy),
                &Object {
                    resource: "file".into(),
                    id: id.into(),
                },
            )
            .unwrap();
        assert_eq!(registered, id == "healthy");
    }
    for changes in next.changes_from(&parent) {
        for (key, value) in changes {
            assert!(key.len() <= NATIVE_MAX_KEY_BYTES);
            assert!(value.is_none_or(|value| value.len() <= NATIVE_MAX_VALUE_BYTES));
        }
    }
    let (verified, verified_modules) = executor
        .execute_with_modules(&state, &context().with_verification(), &txs, parent.clone())
        .unwrap();
    assert_eq!(verified.gas_used, outcome.gas_used);
    assert_eq!(
        serde_json::to_value(verified.receipts).unwrap(),
        serde_json::to_value(outcome.receipts).unwrap()
    );
    assert_eq!(
        verified_modules.changes_from(&parent),
        next.changes_from(&parent)
    );
    assert_eq!(module_state(&parent).serialize_stores(), before);
    assert_eq!(
        module_state(&executor.snapshot().unwrap()).serialize_stores(),
        before
    );
}

#[test]
fn oversized_evm_registration_rolls_back_but_consumes_account_nonce() {
    let (executor, policy) = fixture();
    let before = module_state(&executor.snapshot().unwrap()).serialize_stores();
    let object = oversized_object(policy);
    let (outcome, modules) = super::rollback::execute_with_executor(
        &MockStateDb::new(),
        alloy_primitives::TxKind::Call(ACP_ADDRESS),
        register(policy, &object).into(),
        executor,
    );
    assert_eq!(outcome.executed_tx_indices, Some(vec![0]));
    assert_eq!(outcome.receipts.len(), 1);
    assert!(!outcome.receipts[0].success());
    assert!(outcome.receipts[0].logs().is_empty());
    assert_eq!(outcome.gas_used, NATIVE_LIMIT);
    let signer: alloy_signer_local::PrivateKeySigner = "42".repeat(32).parse().unwrap();
    assert_eq!(outcome.changes.accounts[&signer.address()].nonce, 1);
    assert_eq!(modules.serialize_stores(), before);

    let (executor, policy) = fixture();
    let (outcome, _) = super::rollback::execute_with_executor(
        &MockStateDb::new(),
        alloy_primitives::TxKind::Call(ACP_ADDRESS),
        register(policy, "healthy").into(),
        executor,
    );
    assert!(outcome.receipts[0].success());
    assert_eq!(outcome.receipts[0].logs().len(), 1);
}
