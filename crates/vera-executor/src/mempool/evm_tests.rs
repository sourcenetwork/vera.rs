use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use vera_modules::native_account::NativeNonceStore;

use super::tests::{CHAIN_ID, MockStateDb, test_config};
use super::*;

const GAS: u64 = 21_000;
const FEE: u128 = 1_000;
const COST: u64 = 21_000_000;
const BLOCK_GAS_LIMIT: u64 = 30_000_000;

fn sign(signer: &PrivateKeySigner, tx: TxEip1559) -> Vec<u8> {
    let signature = signer.sign_hash_sync(&tx.signature_hash()).expect("sign");
    TxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718()
}

fn transfer(nonce: u64, to: Address) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit: GAS,
        max_fee_per_gas: FEE,
        to: TxKind::Call(to),
        ..Default::default()
    }
}

fn funded(signer: &PrivateKeySigner, nonce: u64, transfers: u64) -> MockStateDb {
    MockStateDb::new().with_account(signer.address(), nonce, U256::from(COST * transfers))
}

fn rejection(result: Result<TxValidationResult, ExecutionError>) -> String {
    match result {
        Err(ExecutionError::InvalidTx(message)) => message,
        other => panic!("expected an invalid transaction, got {other:?}"),
    }
}

#[tokio::test]
async fn gas_limit_above_the_block_limit_is_rejected() {
    let signer = PrivateKeySigner::random();
    let mut validator = MempoolValidator::new(MockStateDb::new(), test_config(), 0)
        .with_block_gas_limit(BLOCK_GAS_LIMIT);
    let free = |gas_limit| TxEip1559 {
        gas_limit,
        max_fee_per_gas: 0,
        ..transfer(0, Address::ZERO)
    };

    let oversized = sign(&signer, free(BLOCK_GAS_LIMIT + 1));
    assert!(rejection(validator.validate_tx(&oversized).await).contains("exceeds block gas limit"));
    assert!(
        validator.recheck_pending_tx(&oversized).await.is_err(),
        "a retained transaction no block can hold must be evicted"
    );
    let fitting = sign(&signer, free(BLOCK_GAS_LIMIT));
    assert_eq!(validator.validate_tx(&fitting).await.unwrap().nonce, 0);
}

#[tokio::test]
async fn cost_that_overflows_is_rejected() {
    let signer = PrivateKeySigner::random();
    let mut validator = MempoolValidator::new(MockStateDb::new(), test_config(), 0);
    // The gas cost plus this value is 2^256, which wraps to a requirement of zero.
    let wrapping = TxEip1559 {
        value: U256::MAX - U256::from(COST - 1),
        ..transfer(0, Address::ZERO)
    };

    let message = rejection(validator.validate_tx(&sign(&signer, wrapping)).await);
    assert!(message.contains("overflows"), "{message}");
}

#[tokio::test]
async fn recheck_keeps_queued_transactions_and_their_reservations() {
    let signer = PrivateKeySigner::random();
    let state = funded(&signer, 0, 10);
    let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);
    let first = sign(&signer, transfer(0, Address::ZERO));
    let second = sign(&signer, transfer(1, Address::ZERO));
    validator.validate_tx(&first).await.unwrap();
    validator.validate_tx(&second).await.unwrap();

    // A block finalized without either transaction.
    validator.reset(state, NativeNonceStore::default());
    validator.recheck_pending_tx(&first).await.unwrap();
    validator.recheck_pending_tx(&second).await.unwrap();
    let conflicting = sign(&signer, transfer(0, Address::repeat_byte(1)));
    let message = rejection(validator.validate_tx(&conflicting).await);
    assert!(message.contains("expected 2, got 0"), "{message}");
    let third = sign(&signer, transfer(2, Address::ZERO));
    assert_eq!(validator.validate_tx(&third).await.unwrap().nonce, 2);

    // A block finalized the first transaction only.
    validator.reset(funded(&signer, 1, 9), NativeNonceStore::default());
    assert!(validator.recheck_pending_tx(&first).await.is_err());
    validator.recheck_pending_tx(&second).await.unwrap();
    validator.recheck_pending_tx(&third).await.unwrap();
    let message = rejection(validator.validate_tx(&second).await);
    assert!(message.contains("expected 3, got 1"), "{message}");
}

#[tokio::test]
async fn recheck_rebuilds_balance_reservations() {
    let signer = PrivateKeySigner::random();
    let state = funded(&signer, 0, 2);
    let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);
    let pending: Vec<_> = (0..2)
        .map(|nonce| sign(&signer, transfer(nonce, Address::ZERO)))
        .collect();
    for tx in &pending {
        validator.validate_tx(tx).await.unwrap();
    }

    validator.reset(state, NativeNonceStore::default());
    for tx in &pending {
        validator.recheck_pending_tx(tx).await.unwrap();
    }
    let unfunded = sign(&signer, transfer(2, Address::ZERO));
    let message = rejection(validator.validate_tx(&unfunded).await);
    assert!(message.contains("insufficient balance"), "{message}");
}

#[tokio::test]
async fn releasing_reservations_frees_the_nonce_of_a_dropped_transaction() {
    let signer = PrivateKeySigner::random();
    let other = PrivateKeySigner::random();
    let state = funded(&signer, 0, 2).with_account(other.address(), 0, U256::from(COST));
    let mut validator = MempoolValidator::new(state, test_config(), 0);
    let dropped = sign(&signer, transfer(0, Address::ZERO));
    let kept = sign(&other, transfer(0, Address::ZERO));
    validator.validate_tx(&dropped).await.unwrap();
    validator.validate_tx(&kept).await.unwrap();
    let corrected = sign(&signer, transfer(0, Address::repeat_byte(1)));
    let message = rejection(validator.validate_tx(&corrected).await);
    assert!(message.contains("expected 1, got 0"), "{message}");

    validator.release_evm_reservations();
    validator.recheck_pending_tx(&kept).await.unwrap();
    assert_eq!(validator.validate_tx(&corrected).await.unwrap().nonce, 0);
    let message = rejection(validator.validate_tx(&kept).await);
    assert!(message.contains("expected 1, got 0"), "{message}");
}
