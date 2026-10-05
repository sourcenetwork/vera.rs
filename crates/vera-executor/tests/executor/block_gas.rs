use super::*;
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{FixedBytes, TxKind};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use vera_executor::{ExecutionError, ModuleSnapshot, VeraExecutor, precompiles::ACP_ADDRESS};
use vera_modules::acp::abi::IAcp;

const NATIVE_LIMIT: u64 = 1_000_000;
const RECIPIENT: Address = Address::repeat_byte(0x21);

fn policy(valid: bool) -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: if valid {
            Bytes::from_static(b"name: budget\nresources:\n  - name: file\n")
        } else {
            Bytes::from_static(b"invalid")
        },
        marshalType: 1,
    }
    .abi_encode()
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

fn transfer(state: &MockStateDb, nonce: u64, gas_limit: u64) -> (Bytes, Address) {
    let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42)).unwrap();
    state.insert_account(
        signer.address(),
        MockAccount {
            balance: U256::from(1_000_000),
            ..Default::default()
        },
    );
    let tx = TxLegacy {
        chain_id: Some(9001),
        nonce,
        gas_limit,
        to: TxKind::Call(RECIPIENT),
        value: U256::from(1),
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    (
        TxEnvelope::Legacy(tx.into_signed(signature))
            .encoded_2718()
            .into(),
        signer.address(),
    )
}

fn context(gas_limit: u64) -> BlockContext {
    BlockContext::new(
        Header {
            number: 1,
            timestamp: 100,
            gas_limit,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    )
}

fn module_state(snapshot: &ModuleSnapshot) -> vera_executor::ModuleState {
    let view = VeraExecutor::new(9001);
    view.commit_snapshot(1, snapshot.clone()).unwrap();
    view.modules().read().unwrap().clone()
}

fn verify_selected(
    executor: &VeraExecutor,
    state: &MockStateDb,
    context: &BlockContext,
    txs: &[Bytes],
    outcome: &vera_executor::ExecutionOutcome,
    modules: &ModuleSnapshot,
) {
    let selected: Vec<_> = outcome
        .executed_tx_indices
        .as_ref()
        .unwrap()
        .iter()
        .map(|index| txs[*index].clone())
        .collect();
    let (verified, restored) = executor
        .execute_with_modules(
            state,
            &context.clone().with_verification(),
            &selected,
            executor.snapshot().unwrap(),
        )
        .unwrap();
    assert_eq!(verified.gas_used, outcome.gas_used);
    assert_eq!(verified.module_state_root, outcome.module_state_root);
    assert_eq!(
        serde_json::to_value(verified.receipts).unwrap(),
        serde_json::to_value(&outcome.receipts).unwrap()
    );
    assert_eq!(
        module_state(&restored).serialize_stores(),
        module_state(modules).serialize_stores()
    );
}

#[rstest]
#[case(NATIVE_LIMIT - 1, 0)]
#[case(NATIVE_LIMIT, 1)]
fn native_limit_is_reserved_before_nonce_or_module_changes(
    #[case] limit: u64,
    #[case] accepted: u64,
) {
    let executor = VeraExecutor::new(9001);
    let parent = executor.snapshot().unwrap();
    let before = module_state(&parent).serialize_stores();
    let (first, actor) = native(0, policy(true));
    let (second, _) = native(1, policy(true));
    let txs = [first, second];
    let state = MockStateDb::new();
    let context = context(limit);
    let (outcome, next) = executor
        .execute_with_modules(&state, &context, &txs, parent)
        .unwrap();
    assert_eq!(
        outcome.executed_tx_indices,
        Some((0..accepted as usize).collect())
    );
    assert_eq!(
        module_state(&next).nonces.get_nonce(&actor).unwrap(),
        accepted
    );
    assert_eq!(
        module_state(&next).acp.query_policy_ids().unwrap().len(),
        accepted as usize
    );
    assert_eq!(outcome.gas_used, accepted * 5000);
    verify_selected(&executor, &state, &context, &txs, &outcome, &next);
    assert!(matches!(
        executor.execute(&state, &context.with_verification(), &txs),
        Err(ExecutionError::BlockValidation(_))
    ));
    assert_eq!(
        module_state(&executor.snapshot().unwrap()).serialize_stores(),
        before
    );
    let (deferred, _) = native(accepted, policy(true));
    let (_, resumed) = executor
        .execute_with_modules(&state, &self::context(NATIVE_LIMIT), &[deferred], next)
        .unwrap();
    assert_eq!(
        module_state(&resumed).nonces.get_nonce(&actor).unwrap(),
        accepted + 1
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn failed_native_and_reverted_batch_consume_full_capacity(#[case] batch: bool) {
    let executor = VeraExecutor::new(9001);
    let failing = if batch {
        IAcp::batchCallsCall {
            calls: vec![policy(true).into(), policy(false).into()],
        }
        .abi_encode()
    } else {
        policy(false)
    };
    let (failed, actor) = native(0, failing);
    let (deferred, _) = native(1, policy(true));
    let txs = [failed, deferred];
    let state = MockStateDb::new();
    let context = context(NATIVE_LIMIT);
    let (outcome, next) = executor
        .execute_with_modules(&state, &context, &txs, executor.snapshot().unwrap())
        .unwrap();
    assert_eq!(outcome.executed_tx_indices, Some(vec![0]));
    assert_eq!(outcome.gas_used, NATIVE_LIMIT);
    assert!(!outcome.receipts[0].success());
    assert_eq!(outcome.receipts[0].cumulative_gas_used(), NATIVE_LIMIT);
    assert!(outcome.receipts[0].logs().is_empty());
    assert!(
        module_state(&next)
            .acp
            .query_policy_ids()
            .unwrap()
            .is_empty()
    );
    assert_eq!(module_state(&next).nonces.get_nonce(&actor).unwrap(), 1);
    verify_selected(&executor, &state, &context, &txs, &outcome, &next);
    assert!(matches!(
        executor.execute(&state, &context.with_verification(), &txs),
        Err(ExecutionError::BlockValidation(_))
    ));
}

#[rstest]
#[case(21_000, true)]
#[case(21_001, false)]
fn evm_limit_must_fit_before_account_changes(#[case] declared: u64, #[case] accepted: bool) {
    let executor = VeraExecutor::new(9001);
    let state = MockStateDb::new();
    let (tx, actor) = transfer(&state, 0, declared);
    let context = context(21_000);
    let (outcome, next) = executor
        .execute_with_modules(
            &state,
            &context,
            std::slice::from_ref(&tx),
            executor.snapshot().unwrap(),
        )
        .unwrap();
    assert_eq!(
        outcome.executed_tx_indices,
        Some(if accepted { vec![0] } else { vec![] })
    );
    if accepted {
        assert_eq!(outcome.gas_used, 21_000);
        assert_eq!(outcome.changes.accounts[&actor].nonce, 1);
        assert_eq!(outcome.changes.accounts[&RECIPIENT].balance, U256::from(1));
    } else {
        assert_eq!(outcome.gas_used, 0);
        assert!(outcome.changes.accounts.is_empty());
        assert!(matches!(
            executor.execute(
                &state,
                &context.clone().with_verification(),
                std::slice::from_ref(&tx)
            ),
            Err(ExecutionError::BlockValidation(_))
        ));
    }
    verify_selected(&executor, &state, &context, &[tx], &outcome, &next);
    assert_eq!(state.accounts.read().unwrap()[&actor].nonce, 0);
}

#[test]
fn native_and_evm_share_actual_usage_while_reserving_full_limits() {
    let executor = VeraExecutor::new(9001);
    let state = MockStateDb::new();
    let (evm, sender) = transfer(&state, 0, 995_000);
    let (deferred_evm, _) = transfer(&state, 1, 974_001);
    let (native_tx, actor) = native(0, policy(true));
    let (deferred_native, _) = native(1, policy(true));
    let txs = [evm, native_tx, deferred_native, deferred_evm];
    let context = context(NATIVE_LIMIT);
    let (outcome, next) = executor
        .execute_with_modules(&state, &context, &txs, executor.snapshot().unwrap())
        .unwrap();
    assert_eq!(outcome.executed_tx_indices, Some(vec![1, 0]));
    assert_eq!(outcome.gas_used, 26_000);
    assert_eq!(
        outcome
            .receipts
            .iter()
            .map(|r| r.cumulative_gas_used())
            .collect::<Vec<_>>(),
        [5000, 26_000]
    );
    assert_eq!(module_state(&next).nonces.get_nonce(&actor).unwrap(), 1);
    assert_eq!(module_state(&next).acp.query_policy_ids().unwrap().len(), 1);
    assert_eq!(outcome.changes.accounts[&sender].nonce, 1);
    assert_eq!(outcome.changes.accounts[&RECIPIENT].balance, U256::from(1));
    verify_selected(&executor, &state, &context, &txs, &outcome, &next);
    assert!(matches!(
        executor.execute(&state, &context.with_verification(), &txs),
        Err(ExecutionError::BlockValidation(_))
    ));
}

#[test]
fn failed_native_leaves_only_remaining_gas_for_evm() {
    let executor = VeraExecutor::new(9001);
    let state = MockStateDb::new();
    let (failed, _) = native(0, policy(false));
    let (evm, _) = transfer(&state, 0, 21_000);
    let (deferred, _) = transfer(&state, 1, 21_000);
    let txs = [evm, failed, deferred];
    let context = context(NATIVE_LIMIT + 21_000);
    let (outcome, next) = executor
        .execute_with_modules(&state, &context, &txs, executor.snapshot().unwrap())
        .unwrap();
    assert_eq!(outcome.executed_tx_indices, Some(vec![1, 0]));
    assert_eq!(outcome.gas_used, NATIVE_LIMIT + 21_000);
    assert!(!outcome.receipts[0].success());
    assert!(outcome.receipts[1].success());
    verify_selected(&executor, &state, &context, &txs, &outcome, &next);
}
