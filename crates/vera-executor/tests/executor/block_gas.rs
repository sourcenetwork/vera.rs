use super::*;
use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_serialize::CanonicalSerialize as _;
use vera_executor::{ExecutionError, ModuleSnapshot, VeraExecutor, dispatch::ACP_ADDRESS};
use vera_modules::acp::abi::IAcp;

const NATIVE_LIMIT: u64 = 1_000_000;

fn policy(valid: bool) -> Vec<u8> {
    IAcp::createPolicyCall {
        policy: if valid {
            Bytes::from_static(b"name: budget\nresources:\n  - name: file\n")
        } else {
            Bytes::from_static(b"invalid")
        },
        marshalType: 1,
        nonce: Default::default(),
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

fn native_gas_used(tx: &Bytes) -> u64 {
    let executor = VeraExecutor::new(9001);
    let (outcome, _) = executor
        .execute_with_modules(
            &context(NATIVE_LIMIT),
            std::slice::from_ref(tx),
            executor.snapshot(),
        )
        .unwrap();
    assert_eq!(outcome.executed_tx_indices, Some(vec![0]));
    assert_eq!(outcome.receipts.len(), 1);
    assert!(outcome.receipts[0].success());
    assert!(outcome.gas_used > 0 && outcome.gas_used < NATIVE_LIMIT);
    outcome.gas_used
}

const fn context(gas_limit: u64) -> BlockContext {
    BlockContext::new(1, 100, gas_limit)
}

fn module_state(snapshot: &ModuleSnapshot) -> vera_executor::ModuleState {
    let view = VeraExecutor::new(9001);
    view.publish_snapshot(snapshot.clone());
    view.modules().read().unwrap().clone()
}

fn verify_selected(
    executor: &VeraExecutor,
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
            &context.clone().with_verification(),
            &selected,
            executor.snapshot(),
        )
        .unwrap();
    assert_eq!(verified.gas_used, outcome.gas_used);
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
    let parent = executor.snapshot();
    let before = module_state(&parent).serialize_stores();
    let (first, actor) = native(0, policy(true));
    let creation_gas = native_gas_used(&first);
    let (second, _) = native(1, policy(true));
    let txs = [first, second];
    let context = context(limit);
    let (outcome, next) = executor
        .execute_with_modules(&context, &txs, parent)
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
    assert_eq!(outcome.gas_used, accepted * creation_gas);
    verify_selected(&executor, &context, &txs, &outcome, &next);
    assert!(matches!(
        executor.execute_with_modules(&context.with_verification(), &txs, executor.snapshot()),
        Err(ExecutionError::BlockValidation(_))
    ));
    assert_eq!(
        module_state(&executor.snapshot()).serialize_stores(),
        before
    );
    let (deferred, _) = native(accepted, policy(true));
    let (_, resumed) = executor
        .execute_with_modules(&self::context(NATIVE_LIMIT), &[deferred], next)
        .unwrap();
    assert_eq!(
        module_state(&resumed).nonces.get_nonce(&actor).unwrap(),
        accepted + 1
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn failed_native_and_reverted_batch_are_charged_what_they_used(#[case] batch: bool) {
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
    let context = context(NATIVE_LIMIT);
    let (outcome, next) = executor
        .execute_with_modules(&context, &txs, executor.snapshot())
        .unwrap();
    // The refusal leaves less than a full allowance, so the next request waits.
    assert_eq!(outcome.executed_tx_indices, Some(vec![0]));
    let receipt = &outcome.receipts[0];
    assert!(!receipt.success());
    assert!((5_000..NATIVE_LIMIT).contains(&receipt.gas_used));
    assert_eq!(outcome.gas_used, receipt.gas_used);
    assert_eq!(receipt.cumulative_gas_used(), receipt.gas_used);
    assert!(receipt.logs().is_empty());
    let refusal = receipt.refusal.as_ref().unwrap();
    assert_eq!(refusal.kind, vera_domain::RefusalKind::InvalidPolicy);
    assert_eq!(
        refusal.message().starts_with("batch call 2 reverted: "),
        batch
    );
    assert!(
        module_state(&next)
            .acp
            .query_policy_ids()
            .unwrap()
            .is_empty()
    );
    assert_eq!(module_state(&next).nonces.get_nonce(&actor).unwrap(), 1);
    verify_selected(&executor, &context, &txs, &outcome, &next);
    assert!(matches!(
        executor.execute_with_modules(&context.with_verification(), &txs, executor.snapshot()),
        Err(ExecutionError::BlockValidation(_))
    ));
}
