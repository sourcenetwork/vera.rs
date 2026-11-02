//! EVM transaction signer wrapping a secp256k1 private key.

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, keccak256};
use k256::ecdsa::SigningKey;
use k256_native::ecdsa::SigningKey as NativeSigningKey;

use crate::error::ClientError;

const GAS_PRICE: u128 = 1_000_000_000;
const GAS_LIMIT: u64 = 5_000_000;

/// Secp256k1 signer for EVM transactions.
///
/// Used by write methods to construct, sign, and encode [`TxLegacy`] transactions.
#[derive(Debug)]
pub struct EvmSigner {
    inner: NativeSigningKey,
    address: Address,
    chain_id: u64,
}

impl EvmSigner {
    /// Create a signer from a secp256k1 signing key and chain ID.
    pub fn new(signing_key: SigningKey, chain_id: u64) -> Self {
        let key =
            NativeSigningKey::from_slice(&signing_key.to_bytes()).expect("valid secp256k1 key");
        Self::from_native_key(key, chain_id)
    }

    /// Create a signer without converting through the legacy signing key type.
    pub fn from_native_key(signing_key: NativeSigningKey, chain_id: u64) -> Self {
        let point = signing_key.verifying_key().to_sec1_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        Self {
            inner: signing_key,
            address: Address::from_slice(&hash[12..]),
            chain_id,
        }
    }

    /// Parse a hex-encoded private key and create a signer.
    pub fn from_hex(hex: &str, chain_id: u64) -> Result<Self, ClientError> {
        let bytes = zeroize::Zeroizing::new(
            hex::decode(hex.strip_prefix("0x").unwrap_or(hex))
                .map_err(|e| ClientError::Signing(e.to_string()))?,
        );
        let key = NativeSigningKey::from_slice(&bytes)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        Ok(Self::from_native_key(key, chain_id))
    }

    /// Return the Ethereum address derived from this signer's key.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Return the `did:key:` identifier derived from this signer's secp256k1 public key.
    pub fn did(&self) -> String {
        let point = self.inner.verifying_key().to_sec1_point(true);
        vera_crypto::secp256k1::did_from_secp256k1_pubkey(point.as_bytes())
            .expect("valid DID from signer pubkey")
    }

    /// Return the chain ID this signer targets.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Build a [`TxLegacy`], sign it, and return the EIP-2718 encoded bytes.
    pub fn sign_tx(
        &self,
        to: Address,
        calldata: Bytes,
        nonce: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let tx = TxLegacy {
            chain_id: Some(self.chain_id),
            nonce,
            gas_price: GAS_PRICE,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: calldata,
        };

        let (sig, recovery_id) = self
            .inner
            .sign_prehash_recoverable(tx.signature_hash().as_slice());
        if recovery_id.is_x_reduced() {
            return Err(ClientError::Signing(
                "unsupported recovery identifier".into(),
            ));
        }
        let bytes = sig.to_bytes();
        let sig = Signature::new(
            U256::from_be_slice(&bytes[..32]),
            U256::from_be_slice(&bytes[32..]),
            recovery_id.is_y_odd(),
        );
        let signed = tx.into_signed(sig);
        Ok(signed.encoded_2718())
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Transaction;
    use alloy_eips::eip2718::Decodable2718;

    use super::*;

    fn test_key() -> SigningKey {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        SigningKey::from_bytes((&secret).into()).expect("valid key")
    }

    #[test]
    fn from_hex_valid_key() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let signer = EvmSigner::from_hex(hex, 1337).unwrap();
        assert_eq!(signer.chain_id(), 1337);
        assert_ne!(signer.address(), Address::ZERO);
    }

    #[test]
    fn from_hex_invalid_key() {
        let result = EvmSigner::from_hex("not-hex", 1);
        assert!(result.is_err());
    }

    #[test]
    fn address_is_deterministic() {
        let signer1 = EvmSigner::new(test_key(), 1);
        let signer2 = EvmSigner::new(test_key(), 1);
        assert_eq!(signer1.address(), signer2.address());
    }

    #[test]
    fn chain_id_stored() {
        let signer = EvmSigner::new(test_key(), 42);
        assert_eq!(signer.chain_id(), 42);
    }

    #[test]
    fn sign_tx_produces_valid_envelope() {
        let signer = EvmSigner::new(test_key(), 1337);
        let to = Address::repeat_byte(0xab);
        let calldata = Bytes::from(vec![0xde, 0xad]);

        let raw = signer.sign_tx(to, calldata, 0).unwrap();
        let signed = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_slice())
            .expect("valid EIP-2718 encoding");

        assert!(matches!(signed, alloy_consensus::TxEnvelope::Legacy(_)));
    }

    #[test]
    fn sign_tx_correct_chain_id() {
        let signer = EvmSigner::new(test_key(), 42);
        let raw = signer.sign_tx(Address::ZERO, Bytes::new(), 0).unwrap();
        let envelope = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!(envelope.chain_id(), Some(42));
    }

    #[test]
    fn sign_tx_correct_nonce() {
        let signer = EvmSigner::new(test_key(), 1);
        let raw = signer.sign_tx(Address::ZERO, Bytes::new(), 99).unwrap();
        let envelope = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!(envelope.nonce(), 99);
    }

    #[test]
    fn sign_tx_correct_gas_fields() {
        let signer = EvmSigner::new(test_key(), 1);
        let raw = signer.sign_tx(Address::ZERO, Bytes::new(), 0).unwrap();
        let envelope = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!(envelope.gas_limit(), GAS_LIMIT);
    }

    #[test]
    fn sign_tx_correct_recipient() {
        let signer = EvmSigner::new(test_key(), 1);
        let to = Address::repeat_byte(0xcd);
        let raw = signer.sign_tx(to, Bytes::new(), 0).unwrap();
        let envelope = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!(envelope.to(), Some(to));
    }

    #[test]
    fn sign_tx_different_nonces_differ() {
        let signer = EvmSigner::new(test_key(), 1);
        let raw1 = signer.sign_tx(Address::ZERO, Bytes::new(), 0).unwrap();
        let raw2 = signer.sign_tx(Address::ZERO, Bytes::new(), 1).unwrap();
        assert_ne!(raw1, raw2);
    }

    #[test]
    fn native_signing_matches_legacy_signer() {
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;

        let legacy = PrivateKeySigner::from_signing_key(test_key());
        let signer = EvmSigner::new(test_key(), 1337);
        assert_eq!(signer.address(), legacy.address());
        for nonce in [0, 1, 99, u64::MAX] {
            let to = Address::repeat_byte(0xab);
            let input = Bytes::from(vec![0xde, 0xad]);
            let tx = TxLegacy {
                chain_id: Some(1337),
                nonce,
                gas_price: GAS_PRICE,
                gas_limit: GAS_LIMIT,
                to: TxKind::Call(to),
                value: U256::ZERO,
                input: input.clone(),
            };
            let signature = legacy.sign_hash_sync(&tx.signature_hash()).unwrap();
            let expected = tx.into_signed(signature).encoded_2718();
            assert_eq!(signer.sign_tx(to, input, nonce).unwrap(), expected);
        }
    }

    #[test]
    fn signed_transaction_recovers_known_address() {
        use alloy_consensus::transaction::SignerRecoverable;

        let signer = EvmSigner::new(test_key(), 1337);
        let expected: Address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
            .parse()
            .unwrap();
        assert_eq!(signer.address(), expected);
        let raw = signer
            .sign_tx(Address::repeat_byte(0xab), Bytes::from(vec![1, 2, 3]), 7)
            .unwrap();
        let envelope = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!(envelope.recover_signer().unwrap(), expected);
    }

    #[test]
    fn from_hex_rejects_invalid_scalars_and_lengths() {
        assert!(EvmSigner::from_hex(&"00".repeat(32), 1).is_err());
        assert!(EvmSigner::from_hex(&"ff".repeat(32), 1).is_err());
        assert!(EvmSigner::from_hex("01", 1).is_err());
        assert!(EvmSigner::from_hex(&format!("0x{}01", "00".repeat(31)), 1).is_ok());
    }

    #[test]
    fn signing_error_display() {
        let err = ClientError::Signing("bad key".into());
        assert_eq!(err.to_string(), "signing error: bad key");
    }
}
