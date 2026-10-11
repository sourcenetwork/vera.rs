//! Execution error types.

use alloy_primitives::{Address, B256};
use revm::database_interface::DBErrorMarker;
use thiserror::Error;

/// Errors that can occur during block execution.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// State database error.
    #[error("state error: {0}")]
    State(#[from] vera_traits::StateDbError),

    /// Transaction decoding failed.
    #[error("failed to decode transaction: {0}")]
    TxDecode(String),

    /// Transaction execution failed.
    #[error("transaction execution failed: {0}")]
    TxExecution(String),

    /// Invalid transaction.
    #[error("invalid transaction: {0}")]
    InvalidTx(String),

    /// Block validation failed.
    #[error("block validation failed: {0}")]
    BlockValidation(String),

    /// Code not found for hash.
    #[error("code not found: {0}")]
    CodeNotFound(B256),

    /// BLS signature verification, public key deserialization, or DID derivation failed.
    #[error("BLS verification failed: {0}")]
    BlsVerification(String),

    /// secp256k1 signer DID recovery failed.
    #[error("signer DID recovery failed: {0}")]
    SignerDidRecovery(String),

    /// Native transaction chain ID does not match the executor's configured chain ID.
    #[error("chain ID mismatch: expected {expected}, got {got}")]
    ChainIdMismatch {
        /// The chain ID configured on the executor.
        expected: u64,
        /// The chain ID present in the native transaction.
        got: u64,
    },

    /// Native transaction targets an address that is not a known precompile.
    #[error("unknown native tx target: {0}")]
    UnknownNativeTarget(Address),

    /// Native transaction nonce does not match the expected value for the signer DID.
    #[error("nonce mismatch for {did}: expected {expected}, got {got}")]
    NonceMismatch {
        /// The DID of the signer.
        did: String,
        /// The next expected nonce.
        expected: u64,
        /// The nonce present in the transaction.
        got: u64,
    },
}

impl DBErrorMarker for ExecutionError {}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use vera_traits::StateDbError;

    use super::*;

    #[test]
    fn test_state_error_display() {
        let inner = StateDbError::AccountNotFound(Address::ZERO);
        let err = ExecutionError::State(inner);
        assert!(err.to_string().contains("state error"));
    }

    #[test]
    fn test_state_error_from() {
        let inner = StateDbError::LockPoisoned;
        let err: ExecutionError = inner.into();
        assert!(matches!(err, ExecutionError::State(_)));
    }

    #[test]
    fn test_tx_decode_display() {
        let err = ExecutionError::TxDecode("invalid RLP".to_string());
        assert_eq!(err.to_string(), "failed to decode transaction: invalid RLP");
    }

    #[test]
    fn test_tx_execution_display() {
        let err = ExecutionError::TxExecution("out of gas".to_string());
        assert_eq!(err.to_string(), "transaction execution failed: out of gas");
    }

    #[test]
    fn test_invalid_tx_display() {
        let err = ExecutionError::InvalidTx("nonce too low".to_string());
        assert_eq!(err.to_string(), "invalid transaction: nonce too low");
    }

    #[test]
    fn test_block_validation_display() {
        let err = ExecutionError::BlockValidation("wrong parent".to_string());
        assert_eq!(err.to_string(), "block validation failed: wrong parent");
    }

    #[test]
    fn test_code_not_found_display() {
        let hash = B256::ZERO;
        let err = ExecutionError::CodeNotFound(hash);
        assert!(err.to_string().contains("code not found"));
        assert!(err.to_string().contains(&hash.to_string()));
    }

    #[test]
    fn test_error_debug() {
        let err = ExecutionError::TxDecode("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("TxDecode"));
    }

    #[test]
    fn test_bls_verification_display() {
        let err = ExecutionError::BlsVerification("invalid signature".to_string());
        assert_eq!(
            err.to_string(),
            "BLS verification failed: invalid signature"
        );
    }

    #[test]
    fn test_chain_id_mismatch_display() {
        let err = ExecutionError::ChainIdMismatch {
            expected: 9001,
            got: 1,
        };
        assert_eq!(err.to_string(), "chain ID mismatch: expected 9001, got 1");
    }

    #[test]
    fn test_unknown_native_target_display() {
        let addr = Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
        ]);
        let err = ExecutionError::UnknownNativeTarget(addr);
        assert!(err.to_string().contains("unknown native tx target"));
    }

    #[test]
    fn test_nonce_mismatch_display() {
        let err = ExecutionError::NonceMismatch {
            did: "did:key:z6Mk1".to_string(),
            expected: 3,
            got: 0,
        };
        assert_eq!(
            err.to_string(),
            "nonce mismatch for did:key:z6Mk1: expected 3, got 0"
        );
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ExecutionError>();
    }
}
