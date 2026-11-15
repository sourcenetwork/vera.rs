//! Canonical decoding of EVM transaction envelopes.

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;

use crate::ExecutionError;

/// Decode the one EIP-2718 encoding of a transaction that admission and
/// execution accept.
///
/// The transaction hash is the hash of these bytes, so trailing bytes and the
/// string-wrapped network form would give one signed transaction many hashes.
/// A legacy transaction without a chain ID is valid on every deployment and
/// is refused. So is a blob transaction: nothing here stores blobs, and its
/// pooled form carries a sidecar the signature does not cover.
pub(crate) fn decode_envelope(tx_bytes: &[u8]) -> Result<TxEnvelope, ExecutionError> {
    let envelope = TxEnvelope::decode_2718_exact(tx_bytes)
        .map_err(|error| ExecutionError::TxDecode(error.to_string()))?;
    if matches!(&envelope, TxEnvelope::Legacy(signed) if signed.tx().chain_id.is_none()) {
        return Err(ExecutionError::TxDecode(
            "legacy transaction has no chain ID".to_string(),
        ));
    }
    if matches!(envelope, TxEnvelope::Eip4844(_)) {
        return Err(blob_transaction());
    }
    Ok(envelope)
}

pub(crate) fn blob_transaction() -> ExecutionError {
    ExecutionError::TxDecode("blob transactions are not supported".to_string())
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{
        BlobTransactionSidecar, BlobTransactionSidecarVariant, SignableTransaction, TxEip1559,
        TxEip4844, TxEip4844Variant, TxEip4844WithSidecar, TxLegacy,
    };
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, TxKind};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    use super::*;

    fn signer() -> PrivateKeySigner {
        "42".repeat(32).parse().unwrap()
    }

    fn legacy(chain_id: Option<u64>) -> TxEnvelope {
        let tx = TxLegacy {
            chain_id,
            gas_limit: 21_000,
            to: TxKind::Call(Address::ZERO),
            ..Default::default()
        };
        let signature = signer().sign_hash_sync(&tx.signature_hash()).unwrap();
        TxEnvelope::Legacy(tx.into_signed(signature))
    }

    fn typed() -> TxEnvelope {
        let tx = TxEip1559 {
            chain_id: 9001,
            gas_limit: 21_000,
            to: TxKind::Call(Address::ZERO),
            ..Default::default()
        };
        let signature = signer().sign_hash_sync(&tx.signature_hash()).unwrap();
        TxEnvelope::Eip1559(tx.into_signed(signature))
    }

    fn blob(sidecar: Option<BlobTransactionSidecar>) -> TxEnvelope {
        let tx = TxEip4844 {
            chain_id: 9001,
            gas_limit: 21_000,
            blob_versioned_hashes: vec![alloy_primitives::B256::with_last_byte(1)],
            ..Default::default()
        };
        let signature = signer().sign_hash_sync(&tx.signature_hash()).unwrap();
        let variant = match sidecar {
            Some(sidecar) => TxEip4844Variant::TxEip4844WithSidecar(TxEip4844WithSidecar {
                tx,
                sidecar: BlobTransactionSidecarVariant::Eip4844(sidecar),
            }),
            None => TxEip4844Variant::TxEip4844(tx),
        };
        TxEnvelope::Eip4844(variant.into_signed(signature))
    }

    #[test]
    fn a_blob_transaction_is_rejected_with_or_without_its_sidecar() {
        let sidecar = BlobTransactionSidecar::new(
            vec![Default::default()],
            vec![Default::default()],
            vec![Default::default()],
        );
        let plain = blob(None).encoded_2718();
        let pooled = blob(Some(sidecar)).encoded_2718();
        assert_ne!(plain, pooled);
        for bytes in [plain, pooled] {
            assert_eq!(bytes[0], 3);
            TxEnvelope::decode_2718_exact(&bytes).unwrap();
            assert!(matches!(
                decode_envelope(&bytes),
                Err(ExecutionError::TxDecode(reason)) if reason.contains("blob")
            ));
        }
    }

    #[test]
    fn canonical_encodings_decode_to_the_hashed_transaction() {
        for envelope in [legacy(Some(9001)), typed()] {
            let bytes = envelope.encoded_2718();
            let decoded = decode_envelope(&bytes).unwrap();
            assert_eq!(decoded, envelope);
            assert_eq!(*decoded.tx_hash(), alloy_primitives::keccak256(&bytes));
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        for envelope in [legacy(Some(9001)), typed()] {
            let mut bytes = envelope.encoded_2718();
            bytes.push(0);
            assert!(matches!(
                decode_envelope(&bytes),
                Err(ExecutionError::TxDecode(_))
            ));
        }
    }

    #[test]
    fn the_network_form_of_a_typed_transaction_is_rejected() {
        let mut wrapped = Vec::new();
        typed().network_encode(&mut wrapped);
        assert_ne!(wrapped, typed().encoded_2718());
        assert!(matches!(
            decode_envelope(&wrapped),
            Err(ExecutionError::TxDecode(_))
        ));
    }

    #[test]
    fn a_legacy_transaction_without_replay_protection_is_rejected() {
        assert!(matches!(
            decode_envelope(&legacy(None).encoded_2718()),
            Err(ExecutionError::TxDecode(_))
        ));
    }
}
