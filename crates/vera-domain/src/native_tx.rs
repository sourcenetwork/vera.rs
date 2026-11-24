//! BLS12-381 signed native transaction type.

use alloy_primitives::{Address, Bytes, FixedBytes, keccak256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};

use crate::TxId;

/// Custom EIP-2718 type byte for BLS native transactions.
pub const NATIVE_TX_TYPE: u8 = 0x45;

/// A BLS12-381 signed native transaction.
///
/// Wire format: `0x45 || RLP([chain_id, nonce, bls_pubkey, target, calldata, signature])`
///
/// The `calldata` field contains the ABI-encoded call to the target module.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct NativeTx {
    /// Chain identifier for replay protection.
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// BLS12-381 G1 compressed public key (exactly 48 bytes).
    pub bls_pubkey: FixedBytes<48>,
    /// Precompile target address (0x0810, 0x0811, or 0x0812).
    pub target: Address,
    /// ABI-encoded call to the target module.
    pub calldata: Bytes,
    /// BLS12-381 G2 compressed signature (exactly 96 bytes).
    pub signature: FixedBytes<96>,
}

/// The unsigned portion of a [`NativeTx`] (everything except the signature).
///
/// RLP-encoded with the type prefix to produce signing data.
#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct NativeTxPayload {
    /// Chain identifier for replay protection.
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// BLS12-381 G1 compressed public key (exactly 48 bytes).
    pub bls_pubkey: FixedBytes<48>,
    /// Precompile target address (0x0810, 0x0811, or 0x0812).
    pub target: Address,
    /// ABI-encoded call to the target module.
    pub calldata: Bytes,
}

impl NativeTx {
    /// Encode the transaction in wire format: `0x45 || RLP(self)`.
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.length());
        buf.push(NATIVE_TX_TYPE);
        self.encode(&mut buf);
        buf
    }

    /// Decode a transaction from wire format, stripping the `0x45` type prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the first byte is not `0x45` or RLP decoding fails.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, alloy_rlp::Error> {
        if bytes.first() != Some(&NATIVE_TX_TYPE) {
            return Err(alloy_rlp::Error::Custom("missing native tx type byte"));
        }
        alloy_rlp::decode_exact(&bytes[1..])
    }

    /// Produce the bytes that are signed by the BLS key.
    ///
    /// Format: `0x45 || RLP(NativeTxPayload)` — everything except the signature.
    pub fn signing_data(&self) -> Vec<u8> {
        let payload = NativeTxPayload {
            chain_id: self.chain_id,
            nonce: self.nonce,
            bls_pubkey: self.bls_pubkey,
            target: self.target,
            calldata: self.calldata.clone(),
        };
        let mut buf = Vec::with_capacity(1 + payload.length());
        buf.push(NATIVE_TX_TYPE);
        payload.encode(&mut buf);
        buf
    }

    /// Compute the transaction identifier: `keccak256(signing_data())`.
    ///
    /// Hashes the payload (excluding signature) so that the tx_id is stable
    /// across different valid signatures of the same transaction.
    pub fn tx_id(&self) -> TxId {
        TxId(keccak256(self.signing_data()))
    }

    /// Returns `true` if the byte matches the native tx type prefix.
    #[must_use]
    pub const fn is_native_tx(first_byte: u8) -> bool {
        first_byte == NATIVE_TX_TYPE
    }
}

#[cfg(test)]
mod tests {
    use alloy_rlp::Decodable;

    use super::*;

    fn sample_tx() -> NativeTx {
        NativeTx {
            chain_id: 1,
            nonce: 42,
            bls_pubkey: FixedBytes::from([0xAA; 48]),
            target: Address::from([
                0x08, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            calldata: Bytes::from(vec![0xDE, 0xAD]),
            signature: FixedBytes::from([0xBB; 96]),
        }
    }

    #[test]
    fn rlp_encode_decode_roundtrip() {
        let tx = sample_tx();
        let wire = tx.encode_wire();
        assert_eq!(wire[0], NATIVE_TX_TYPE);
        let decoded = NativeTx::decode_wire(&wire).expect("decode");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn signing_data_excludes_signature() {
        let tx = sample_tx();
        let signing = tx.signing_data();
        assert_eq!(signing[0], NATIVE_TX_TYPE);

        let payload = NativeTxPayload::decode(&mut &signing[1..]).expect("decode payload");
        assert_eq!(payload.chain_id, tx.chain_id);
        assert_eq!(payload.nonce, tx.nonce);
        assert_eq!(payload.bls_pubkey, tx.bls_pubkey);
        assert_eq!(payload.target, tx.target);
        assert_eq!(payload.calldata, tx.calldata);

        assert_ne!(signing.len(), tx.encode_wire().len());
    }

    #[test]
    fn format_detection() {
        assert!(NativeTx::is_native_tx(0x45));
        assert!(!NativeTx::is_native_tx(0x02));
        assert!(!NativeTx::is_native_tx(0x00));
    }

    #[test]
    fn tx_id_is_deterministic() {
        let tx = sample_tx();
        assert_eq!(tx.tx_id(), tx.tx_id());
    }

    #[test]
    fn tx_id_differs_by_content() {
        let tx1 = sample_tx();
        let mut tx2 = sample_tx();
        tx2.calldata = Bytes::from(vec![0xFF, 0xFF]);
        assert_ne!(tx1.tx_id(), tx2.tx_id());
    }

    #[test]
    fn tx_id_ignores_signature() {
        let tx1 = sample_tx();
        let mut tx2 = sample_tx();
        tx2.signature = FixedBytes::from([0xCC; 96]);
        assert_eq!(tx1.tx_id(), tx2.tx_id());
    }

    #[test]
    fn decode_wire_rejects_wrong_type_byte() {
        let tx = sample_tx();
        let mut wire = tx.encode_wire();
        wire[0] = 0x02;
        assert!(NativeTx::decode_wire(&wire).is_err());
    }

    #[test]
    fn decode_wire_rejects_empty() {
        assert!(NativeTx::decode_wire(&[]).is_err());
    }

    #[test]
    fn decode_wire_rejects_trailing_bytes() {
        let tx = sample_tx();
        let mut wire = tx.encode_wire();
        wire.push(0xFF);
        assert!(NativeTx::decode_wire(&wire).is_err());
    }
}
