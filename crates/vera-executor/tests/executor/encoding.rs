//! Only the canonical encoding of a replay-protected transaction executes.

use super::*;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::TxKind;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use vera_executor::{ExecutionError, ExecutionOutcome, VeraExecutor};

fn signer(state: &MockStateDb) -> PrivateKeySigner {
    let signer: PrivateKeySigner = "42".repeat(32).parse().unwrap();
    state.insert_account(
        signer.address(),
        MockAccount {
            balance: U256::from(10).pow(U256::from(18)),
            ..Default::default()
        },
    );
    signer
}

fn legacy(state: &MockStateDb, chain_id: Option<u64>) -> TxEnvelope {
    let tx = TxLegacy {
        chain_id,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(0x21)),
        ..Default::default()
    };
    let signature = signer(state).sign_hash_sync(&tx.signature_hash()).unwrap();
    TxEnvelope::Legacy(tx.into_signed(signature))
}

fn typed(state: &MockStateDb) -> TxEnvelope {
    let tx = TxEip1559 {
        chain_id: 9001,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(0x21)),
        ..Default::default()
    };
    let signature = signer(state).sign_hash_sync(&tx.signature_hash()).unwrap();
    TxEnvelope::Eip1559(tx.into_signed(signature))
}

fn execute(
    state: &MockStateDb,
    tx: Vec<u8>,
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
    let executor = VeraExecutor::new(9001);
    executor
        .execute_with_modules(state, &context, &[tx.into()], executor.snapshot())
        .map(|(outcome, _)| outcome)
}

fn assert_refused(state: &MockStateDb, tx: Vec<u8>) {
    let built = execute(state, tx.clone(), false).unwrap();
    assert_eq!(built.executed_tx_indices, Some(vec![]));
    assert!(built.receipts.is_empty());
    assert!(matches!(
        execute(state, tx, true),
        Err(ExecutionError::TxDecode(_))
    ));
}

#[test]
fn canonical_encodings_execute_under_the_envelope_hash() {
    let state = MockStateDb::new();
    for envelope in [legacy(&state, Some(9001)), typed(&state)] {
        let outcome = execute(&state, envelope.encoded_2718(), true).unwrap();
        assert!(outcome.receipts[0].success());
        assert_eq!(outcome.receipts[0].tx_hash, *envelope.tx_hash());
    }
}

#[test]
fn trailing_bytes_are_not_executed() {
    let state = MockStateDb::new();
    for envelope in [legacy(&state, Some(9001)), typed(&state)] {
        let mut tx = envelope.encoded_2718();
        tx.push(0);
        assert_refused(&state, tx);
    }
}

#[test]
fn the_network_form_of_a_typed_transaction_is_not_executed() {
    let state = MockStateDb::new();
    let mut wrapped = Vec::new();
    typed(&state).network_encode(&mut wrapped);
    assert_refused(&state, wrapped);
}

#[test]
fn a_legacy_transaction_without_a_chain_id_is_not_executed() {
    let state = MockStateDb::new();
    assert_refused(&state, legacy(&state, None).encoded_2718());
}
