use super::*;
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{TxKind, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use vera_executor::{ExecutionError, ExecutionOutcome, VeraExecutor};

const CONTRACT: Address = Address::repeat_byte(0x11);

fn fixture() -> MockStateDb {
    let state = MockStateDb::new();
    // Increment slot zero. Nonempty calldata reverts the write.
    let code = Bytes::from_static(&[
        0x5f, 0x54, 0x60, 0x01, 0x01, 0x5f, 0x55, 0x36, 0x15, 0x60, 0x10, 0x57, 0x5f, 0x5f, 0xfd,
        0x00, 0x5b, 0x00,
    ]);
    let code_hash = keccak256(&code);
    state.insert_code(code_hash, code);
    state.insert_account(
        CONTRACT,
        MockAccount {
            code_hash,
            ..Default::default()
        },
    );
    state
}

fn signed(state: &MockStateDb, key: u8, nonce: u64, revert: bool) -> (Address, Bytes) {
    let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(key)).unwrap();
    state.insert_account(
        signer.address(),
        MockAccount {
            balance: U256::from(10).pow(U256::from(18)),
            ..Default::default()
        },
    );
    let tx = TxLegacy {
        chain_id: Some(9001),
        nonce,
        gas_limit: 100_000,
        to: TxKind::Call(CONTRACT),
        input: if revert {
            Bytes::from_static(&[1])
        } else {
            Bytes::new()
        },
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    (
        signer.address(),
        TxEnvelope::Legacy(tx.into_signed(signature))
            .encoded_2718()
            .into(),
    )
}

fn execute(
    state: &MockStateDb,
    txs: &[Bytes],
    vera: bool,
    verify: bool,
) -> Result<ExecutionOutcome, ExecutionError> {
    let mut context = BlockContext::new(
        Header {
            number: 1,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        B256::ZERO,
        B256::ZERO,
    );
    context.is_verification = verify;
    if vera {
        let executor = VeraExecutor::new(9001);
        executor
            .execute_with_modules(state, &context, txs, executor.snapshot())
            .map(|(outcome, _)| outcome)
    } else {
        RevmExecutor::new(9001).execute(state, &context, txs)
    }
}

#[rstest]
#[case(false)]
#[case(true)]
fn consecutive_operations_advance_account_and_storage(#[case] vera: bool) {
    let state = fixture();
    let (actor, first) = signed(&state, 0x42, 0, false);
    let (_, second) = signed(&state, 0x42, 1, false);
    let outcome = execute(&state, &[first, second], vera, true).unwrap();
    assert_eq!(outcome.receipts.len(), 2);
    assert!(outcome.receipts.iter().all(|receipt| receipt.success()));
    assert_eq!(outcome.changes.accounts[&actor].nonce, 2);
    assert_eq!(
        outcome.changes.accounts[&CONTRACT].storage[&U256::ZERO],
        U256::from(2)
    );
    let original = state.accounts.read().unwrap();
    assert_eq!(original[&actor].nonce, 0);
    assert!(original[&CONTRACT].storage.is_empty());
}

#[rstest]
#[case(false)]
#[case(true)]
fn verification_rejects_repeated_operation(#[case] vera: bool) {
    let state = fixture();
    let (_, tx) = signed(&state, 0x42, 0, false);
    assert!(execute(&state, &[tx.clone(), tx], vera, true).is_err());
}

#[rstest]
#[case(false)]
#[case(true)]
fn different_actors_observe_prior_storage_writes(#[case] vera: bool) {
    let state = fixture();
    let (_, first) = signed(&state, 0x42, 0, false);
    let (_, second) = signed(&state, 0x43, 0, false);
    let outcome = execute(&state, &[first, second], vera, true).unwrap();
    assert!(outcome.receipts.iter().all(|receipt| receipt.success()));
    assert_eq!(
        outcome.changes.accounts[&CONTRACT].storage[&U256::ZERO],
        U256::from(2)
    );
}

#[test]
fn skipped_operation_preserves_prior_changes() {
    let state = fixture();
    let (actor, first) = signed(&state, 0x42, 0, false);
    let (_, invalid) = signed(&state, 0x42, 7, false);
    let (_, second) = signed(&state, 0x42, 1, false);
    let outcome = execute(&state, &[first, invalid, second], true, false).unwrap();
    assert_eq!(outcome.executed_tx_indices, Some(vec![0, 2]));
    assert_eq!(outcome.changes.accounts[&actor].nonce, 2);
    assert_eq!(
        outcome.changes.accounts[&CONTRACT].storage[&U256::ZERO],
        U256::from(2)
    );
}

#[rstest]
#[case(false)]
#[case(true)]
fn reverted_operation_consumes_sequence_without_storage_write(#[case] vera: bool) {
    let state = fixture();
    let (actor, first) = signed(&state, 0x42, 0, true);
    let (_, second) = signed(&state, 0x42, 1, false);
    let outcome = execute(&state, &[first, second], vera, true).unwrap();
    assert!(!outcome.receipts[0].success());
    assert!(outcome.receipts[1].success());
    assert_eq!(outcome.changes.accounts[&actor].nonce, 2);
    assert_eq!(
        outcome.changes.accounts[&CONTRACT].storage[&U256::ZERO],
        U256::from(1)
    );
}
