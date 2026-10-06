//! Mempool transaction validator — CheckTx equivalent with branched state.
//!
//! Validates both EVM (secp256k1) and BLS native transactions, maintaining
//! branched state across calls so sequential validations from the same sender
//! see each other's nonce increments.

use std::collections::BTreeMap;

use alloy_primitives::{Bytes, U256};
use vera_crypto::bls;
use vera_domain::NativeTx;
use vera_modules::native_account::NativeNonceStore;
use vera_overlay::OverlayState;
use vera_qmdb::{AccountUpdate, ChangeSet};
use vera_traits::StateDb;

use crate::precompiles::{ACP_ADDRESS, BULLETIN_ADDRESS, VALIDATOR_REGISTRY_ADDRESS, VERA_ADDRESS};
use crate::{ExecutionConfig, ExecutionError, TxValidator};

/// Result of validating a transaction for mempool admission.
#[derive(Clone, Debug)]
pub struct TxValidationResult {
    /// Sender identity — Ethereum address (hex) for EVM txs, `did:key:` for BLS native txs.
    pub sender: String,
    /// Transaction nonce.
    pub nonce: u64,
    /// Whether this is a native BLS transaction.
    pub is_native: bool,
}

/// Pre-validated native BLS transaction.
///
/// Contains the results of expensive stateless validation (BLS signature
/// verification and DID derivation) so that the stateful nonce check can
/// run separately inside the mutex without repeating the crypto work.
#[derive(Clone, Debug)]
pub struct PreValidatedNativeTx {
    /// `did:key:` identifier derived from the BLS public key.
    pub signer_did: String,
    /// Transaction nonce from the wire format.
    pub nonce: u64,
}

/// Stateful transaction validator — mempool admission gate.
///
/// Maintains branched state across calls so sequential validations
/// from the same sender see each other's nonce increments.
/// Call [`MempoolValidator::reset`] after each block finalization.
#[derive(Clone, Debug)]
pub struct MempoolValidator<S> {
    config: ExecutionConfig,
    base: S,
    evm_changes: ChangeSet,
    native_nonces: NativeNonceStore,
    base_fee: u64,
    native_only: bool,
}

impl<S: StateDb> MempoolValidator<S> {
    /// Create a new mempool validator against the given base state.
    pub fn new(base: S, config: ExecutionConfig, base_fee: u64) -> Self {
        Self {
            config,
            base,
            evm_changes: ChangeSet::new(),
            native_nonces: NativeNonceStore::default(),
            base_fee,
            native_only: false,
        }
    }

    /// Reject legacy EVM submissions in a native-only deployment.
    #[must_use]
    pub const fn with_native_only(mut self, enabled: bool) -> Self {
        self.native_only = enabled;
        self
    }

    /// Reset branched state after block finalization.
    ///
    /// Native nonces are loaded from the finalized module state so the
    /// validator correctly rejects replayed nonces and accepts the next
    /// valid nonce for each BLS identity. Recheck retained transactions in
    /// admission order before accepting new requests.
    pub fn reset(&mut self, base: S, native_nonces: NativeNonceStore) {
        self.base = base;
        self.evm_changes = ChangeSet::new();
        self.native_nonces = native_nonces;
    }

    /// Recheck immutable transactions already authenticated at admission.
    ///
    /// Call once per retained transaction, in admission order, after [`Self::reset`].
    /// Native requests rebuild nonce reservations without repeating signature
    /// verification. EVM requests check nonce/balance against committed base state.
    pub async fn recheck_pending_tx(&mut self, tx_bytes: &[u8]) -> Result<(), ExecutionError> {
        if tx_bytes.is_empty() {
            return Err(ExecutionError::TxDecode("empty transaction".to_string()));
        }
        if NativeTx::is_native_tx(tx_bytes[0]) {
            self.recheck_native_tx(tx_bytes)
        } else {
            self.recheck_evm_tx(tx_bytes).await
        }
    }

    async fn recheck_evm_tx(&self, tx_bytes: &[u8]) -> Result<(), ExecutionError> {
        let validator = TxValidator::new(&self.config, self.base_fee);
        let bytes = Bytes::from(tx_bytes.to_vec());
        validator.validate(&bytes, &self.base).await?;
        Ok(())
    }

    fn recheck_native_tx(&mut self, tx_bytes: &[u8]) -> Result<(), ExecutionError> {
        let native_tx = NativeTx::decode_wire(tx_bytes)
            .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;

        if native_tx.chain_id != self.config.chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: native_tx.chain_id,
            });
        }

        if native_tx.target != ACP_ADDRESS
            && native_tx.target != BULLETIN_ADDRESS
            && native_tx.target != VERA_ADDRESS
            && native_tx.target != VALIDATOR_REGISTRY_ADDRESS
        {
            return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
        }

        let pubkey = bls::deserialize_pubkey(native_tx.bls_pubkey.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("pubkey: {e}")))?;
        let signer_did = bls::did_from_bls_pubkey(&pubkey)
            .map_err(|e| ExecutionError::BlsVerification(format!("DID: {e}")))?;
        self.admit_native(&PreValidatedNativeTx {
            signer_did,
            nonce: native_tx.nonce,
        })?;
        Ok(())
    }

    /// Stateless pre-validation for native BLS transactions.
    ///
    /// Performs decode, chain ID check, target check, BLS signature
    /// verification, and DID derivation — all without needing mutable
    /// state. Call this **outside** the ledger mutex, then pass the
    /// result to [`admit_native`] inside the mutex for the nonce check.
    pub fn pre_validate_native(
        chain_id: u64,
        tx_bytes: &[u8],
    ) -> Result<PreValidatedNativeTx, ExecutionError> {
        let native_tx = NativeTx::decode_wire(tx_bytes)
            .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;

        if native_tx.chain_id != chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: chain_id,
                got: native_tx.chain_id,
            });
        }

        if native_tx.target != ACP_ADDRESS
            && native_tx.target != BULLETIN_ADDRESS
            && native_tx.target != VERA_ADDRESS
            && native_tx.target != VALIDATOR_REGISTRY_ADDRESS
        {
            return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
        }

        let signer_did = bls::verify_and_identify(
            native_tx.bls_pubkey.as_slice(),
            &native_tx.signing_data(),
            native_tx.signature.as_slice(),
        )
        .map_err(|e| ExecutionError::BlsVerification(format!("signature: {e}")))?;

        Ok(PreValidatedNativeTx {
            signer_did,
            nonce: native_tx.nonce,
        })
    }

    /// Admit a pre-validated native BLS transaction into branched state.
    ///
    /// Only performs the nonce check — all expensive crypto was already
    /// done by [`pre_validate_native`]. Call this inside the mutex.
    pub fn admit_native(
        &mut self,
        pre: &PreValidatedNativeTx,
    ) -> Result<TxValidationResult, ExecutionError> {
        self.native_nonces
            .check_and_increment(&pre.signer_did, pre.nonce)
            .map_err(|e| match e {
                vera_modules::native_account::NonceError::Mismatch { did, expected, got } => {
                    ExecutionError::NonceMismatch { did, expected, got }
                }
                vera_modules::native_account::NonceError::Overflow(did) => {
                    ExecutionError::InvalidTx(format!("nonce overflow for {did}"))
                }
                vera_modules::native_account::NonceError::Malformed(did) => {
                    ExecutionError::InvalidTx(format!("stored nonce for {did} is malformed"))
                }
            })?;

        Ok(TxValidationResult {
            sender: pre.signer_did.clone(),
            nonce: pre.nonce,
            is_native: true,
        })
    }

    /// Validate a transaction for mempool admission.
    ///
    /// Detects format by first byte (`0x45` = BLS native, else EVM).
    /// On success, increments the sender's nonce in the branched state.
    ///
    /// For native BLS transactions, prefer using [`pre_validate_native`]
    /// + [`admit_native`] to avoid holding locks during BLS verification.
    pub async fn validate_tx(
        &mut self,
        tx_bytes: &[u8],
    ) -> Result<TxValidationResult, ExecutionError> {
        if self.native_only
            && !tx_bytes
                .first()
                .is_some_and(|byte| NativeTx::is_native_tx(*byte))
        {
            return Err(ExecutionError::InvalidTx(
                "EVM transactions are disabled in pipelined mode".into(),
            ));
        }
        if tx_bytes.is_empty() {
            return Err(ExecutionError::TxDecode("empty transaction".to_string()));
        }
        if NativeTx::is_native_tx(tx_bytes[0]) {
            self.validate_native_tx(tx_bytes)
        } else {
            self.validate_evm_tx(tx_bytes).await
        }
    }

    async fn validate_evm_tx(
        &mut self,
        tx_bytes: &[u8],
    ) -> Result<TxValidationResult, ExecutionError> {
        let overlay = OverlayState::new(self.base.clone(), self.evm_changes.clone());
        let validator = TxValidator::new(&self.config, self.base_fee);
        let bytes = Bytes::from(tx_bytes.to_vec());
        let validated = validator.validate(&bytes, &overlay).await?;

        let new_nonce = validated.nonce.checked_add(1).ok_or_else(|| {
            ExecutionError::InvalidTx(format!("nonce overflow for {:?}", validated.sender))
        })?;

        // Reserve balance for gas + value (matches Cosmos SDK AnteHandler behavior:
        // fees are deducted from branched checkState during CheckTx).
        let reserved =
            U256::from(validated.gas_limit) * U256::from(validated.max_fee) + validated.value;

        if let Some(account) = self.evm_changes.accounts.get_mut(&validated.sender) {
            account.nonce = new_nonce;
            account.balance = account.balance.saturating_sub(reserved);
        } else {
            let balance = self.base.balance(&validated.sender).await?;
            let code_hash = self.base.code_hash(&validated.sender).await?;
            self.evm_changes.accounts.insert(
                validated.sender,
                AccountUpdate {
                    created: false,
                    selfdestructed: false,
                    nonce: new_nonce,
                    balance: balance.saturating_sub(reserved),
                    code_hash,
                    code: None,
                    storage: BTreeMap::new(),
                },
            );
        }

        Ok(TxValidationResult {
            sender: format!("{:?}", validated.sender),
            nonce: validated.nonce,
            is_native: false,
        })
    }

    fn validate_native_tx(
        &mut self,
        tx_bytes: &[u8],
    ) -> Result<TxValidationResult, ExecutionError> {
        let native_tx = NativeTx::decode_wire(tx_bytes)
            .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;

        if native_tx.chain_id != self.config.chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: native_tx.chain_id,
            });
        }

        if native_tx.target != ACP_ADDRESS
            && native_tx.target != BULLETIN_ADDRESS
            && native_tx.target != VERA_ADDRESS
            && native_tx.target != VALIDATOR_REGISTRY_ADDRESS
        {
            return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
        }

        let pubkey = bls::deserialize_pubkey(native_tx.bls_pubkey.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("pubkey: {e}")))?;

        let signing_data = native_tx.signing_data();
        bls::verify(&pubkey, &signing_data, native_tx.signature.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("signature: {e}")))?;

        let signer_did = bls::did_from_bls_pubkey(&pubkey)
            .map_err(|e| ExecutionError::BlsVerification(format!("DID: {e}")))?;

        self.native_nonces
            .check_and_increment(&signer_did, native_tx.nonce)
            .map_err(|e| match e {
                vera_modules::native_account::NonceError::Mismatch { did, expected, got } => {
                    ExecutionError::NonceMismatch { did, expected, got }
                }
                vera_modules::native_account::NonceError::Overflow(did) => {
                    ExecutionError::InvalidTx(format!("nonce overflow for {did}"))
                }
                vera_modules::native_account::NonceError::Malformed(did) => {
                    ExecutionError::InvalidTx(format!("stored nonce for {did} is malformed"))
                }
            })?;

        Ok(TxValidationResult {
            sender: signer_did,
            nonce: native_tx.nonce,
            is_native: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy_primitives::{Address, B256, FixedBytes, KECCAK256_EMPTY, TxKind, U256};
    use alloy_rlp::Encodable;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use vera_qmdb::ChangeSet;
    use vera_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};

    use super::*;

    #[derive(Clone, Debug)]
    struct MockStateDb {
        accounts: BTreeMap<Address, (u64, U256)>,
    }

    impl MockStateDb {
        fn new() -> Self {
            Self {
                accounts: BTreeMap::new(),
            }
        }

        fn with_account(mut self, address: Address, nonce: u64, balance: U256) -> Self {
            self.accounts.insert(address, (nonce, balance));
            self
        }
    }

    impl StateDbRead for MockStateDb {
        async fn nonce(&self, address: &Address) -> Result<u64, StateDbError> {
            Ok(self.accounts.get(address).map(|(n, _)| *n).unwrap_or(0))
        }
        async fn balance(&self, address: &Address) -> Result<U256, StateDbError> {
            Ok(self
                .accounts
                .get(address)
                .map(|(_, b)| *b)
                .unwrap_or(U256::ZERO))
        }
        async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
            Ok(KECCAK256_EMPTY)
        }
        async fn code(&self, _code_hash: &B256) -> Result<Bytes, StateDbError> {
            Ok(Bytes::new())
        }
        async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }
    }

    impl StateDbWrite for MockStateDb {
        async fn commit(&self, _changes: ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        async fn compute_root(&self, _changes: &ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        fn merge_changes(&self, _older: ChangeSet, newer: ChangeSet) -> ChangeSet {
            newer
        }
    }

    impl StateDb for MockStateDb {
        async fn state_root(&self) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
    }

    const CHAIN_ID: u64 = 9001;

    fn test_config() -> ExecutionConfig {
        ExecutionConfig::new(CHAIN_ID)
    }

    fn signed_evm_tx(signer: &PrivateKeySigner, nonce: u64) -> Vec<u8> {
        let tx = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce,
            gas_limit: 21000,
            max_fee_per_gas: 1000,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
        };
        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).expect("sign");
        let signed = tx.into_signed(signature);
        let envelope = TxEnvelope::Eip1559(signed);
        let mut buf = Vec::new();
        envelope.encode(&mut buf);
        buf
    }

    fn test_bls_keypair() -> (ark_bls12_381::Fr, Vec<u8>) {
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();
        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        (sk, pk_bytes)
    }

    fn signed_native_tx(sk: &ark_bls12_381::Fr, pk_bytes: &[u8], nonce: u64) -> Vec<u8> {
        let mut tx = NativeTx {
            chain_id: CHAIN_ID,
            nonce,
            bls_pubkey: FixedBytes::from_slice(pk_bytes),
            target: Address::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
            ]),
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        tx.encode_wire()
    }

    #[tokio::test]
    async fn pipeline_admission_rejects_valid_evm_and_preserves_native_admission() {
        let signer = PrivateKeySigner::random();
        let state = MockStateDb::new().with_account(signer.address(), 0, U256::from(21_000_001));
        let mut validator = MempoolValidator::new(state, test_config(), 0).with_native_only(true);
        let error = validator
            .validate_tx(&signed_evm_tx(&signer, 0))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("EVM transactions are disabled"));
        let (secret, public) = test_bls_keypair();
        let result = validator
            .validate_tx(&signed_native_tx(&secret, &public, 0))
            .await
            .unwrap();
        assert!(result.is_native);
        assert_eq!(result.nonce, 0);
        validator.reset(MockStateDb::new(), NativeNonceStore::default());
        assert!(
            validator
                .validate_tx(&signed_evm_tx(&signer, 0))
                .await
                .unwrap_err()
                .to_string()
                .contains("EVM transactions are disabled")
        );
    }

    // -- EVM validation tests --

    #[tokio::test]
    async fn evm_valid_tx() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 + 1);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx_bytes = signed_evm_tx(&signer, 0);
        let result = validator.validate_tx(&tx_bytes).await.unwrap();
        assert!(!result.is_native);
        assert_eq!(result.nonce, 0);
    }

    #[tokio::test]
    async fn evm_sequential_nonces() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 * 10);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        let r0 = validator.validate_tx(&tx0).await.unwrap();
        assert_eq!(r0.nonce, 0);

        let tx1 = signed_evm_tx(&signer, 1);
        let r1 = validator.validate_tx(&tx1).await.unwrap();
        assert_eq!(r1.nonce, 1);
    }

    #[tokio::test]
    async fn evm_nonce_replay_rejected() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 * 10);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        validator.validate_tx(&tx0).await.unwrap();

        let tx0_replay = signed_evm_tx(&signer, 0);
        let err = validator.validate_tx(&tx0_replay).await.unwrap_err();
        assert!(matches!(err, ExecutionError::InvalidTx(_)));
    }

    #[tokio::test]
    async fn evm_garbage_bytes_rejected() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let err = validator.validate_tx(&[0xFF, 0xFF]).await.unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }

    // -- BLS native validation tests --

    #[tokio::test]
    async fn native_valid_tx() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx_bytes = signed_native_tx(&sk, &pk_bytes, 0);
        let result = validator.validate_tx(&tx_bytes).await.unwrap();
        assert!(result.is_native);
        assert_eq!(result.nonce, 0);
        assert!(result.sender.starts_with("did:key:"));
    }

    #[tokio::test]
    async fn native_sequential_nonces() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
        let r0 = validator.validate_tx(&tx0).await.unwrap();
        assert_eq!(r0.nonce, 0);

        let tx1 = signed_native_tx(&sk, &pk_bytes, 1);
        let r1 = validator.validate_tx(&tx1).await.unwrap();
        assert_eq!(r1.nonce, 1);
    }

    #[tokio::test]
    async fn native_nonce_replay_rejected() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
        validator.validate_tx(&tx0).await.unwrap();

        let tx0_replay = signed_native_tx(&sk, &pk_bytes, 0);
        let err = validator.validate_tx(&tx0_replay).await.unwrap_err();
        assert!(matches!(err, ExecutionError::NonceMismatch { .. }));
    }

    #[tokio::test]
    async fn native_wrong_chain_id() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let mut tx = NativeTx {
            chain_id: 999,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: Address::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
            ]),
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        let wire = tx.encode_wire();

        let err = validator.validate_tx(&wire).await.unwrap_err();
        assert!(matches!(
            err,
            ExecutionError::ChainIdMismatch {
                expected: CHAIN_ID,
                got: 999,
            }
        ));
    }

    #[tokio::test]
    async fn native_invalid_bls_sig() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx = NativeTx {
            chain_id: CHAIN_ID,
            nonce: 0,
            bls_pubkey: FixedBytes::from([0xFF; 48]),
            target: Address::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
            ]),
            calldata: Bytes::new(),
            signature: FixedBytes::from([0xBB; 96]),
        };
        let wire = tx.encode_wire();

        let err = validator.validate_tx(&wire).await.unwrap_err();
        assert!(matches!(err, ExecutionError::BlsVerification(_)));
    }

    #[tokio::test]
    async fn native_garbage_bytes() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let err = validator
            .validate_tx(&[0x45, 0xFF, 0xFF])
            .await
            .unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }

    // -- Balance reservation tests --

    #[tokio::test]
    async fn evm_balance_exhaustion_rejects_second_tx() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        // Enough for exactly one tx: gas_limit(21000) * max_fee(1000) = 21_000_000
        let balance = U256::from(21_000_000u64);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        validator.validate_tx(&tx0).await.unwrap();

        // Second tx should fail: reserved balance leaves 0 remaining.
        let tx1 = signed_evm_tx(&signer, 1);
        let err = validator.validate_tx(&tx1).await.unwrap_err();
        assert!(matches!(err, ExecutionError::InvalidTx(_)));
    }

    // -- Native target check tests --

    #[tokio::test]
    async fn native_unknown_target_rejected() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let bad_target = Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
        ]);

        let mut tx = NativeTx {
            chain_id: CHAIN_ID,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: bad_target,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        let wire = tx.encode_wire();

        let err = validator.validate_tx(&wire).await.unwrap_err();
        assert!(matches!(err, ExecutionError::UnknownNativeTarget(_)));
    }

    #[tokio::test]
    async fn native_membership_admission_and_recheck() {
        let (key, public) = test_bls_keypair();
        let mut request = NativeTx::decode_wire(&signed_native_tx(&key, &public, 0)).unwrap();
        request.target = VALIDATOR_REGISTRY_ADDRESS;
        request.signature =
            FixedBytes::from_slice(&bls::sign(&key, &request.signing_data()).unwrap());
        let wire = request.encode_wire();
        let mut validator = MempoolValidator::new(MockStateDb::new(), test_config(), 0);
        let validated =
            MempoolValidator::<MockStateDb>::pre_validate_native(CHAIN_ID, &wire).unwrap();
        validator.admit_native(&validated).unwrap();
        validator.reset(MockStateDb::new(), NativeNonceStore::default());
        validator.recheck_pending_tx(&wire).await.unwrap();
        let mut legacy_entry = MempoolValidator::new(MockStateDb::new(), test_config(), 0);
        legacy_entry.validate_tx(&wire).await.unwrap();
        assert!(legacy_entry.validate_tx(&wire).await.is_err());
    }

    // -- Empty tx tests --

    #[tokio::test]
    async fn empty_tx_rejected() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let err = validator.validate_tx(&[]).await.unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }

    // -- Reset tests --

    #[tokio::test]
    async fn reset_clears_nonce_state() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);

        let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
        validator.validate_tx(&tx0).await.unwrap();

        // After reset with empty nonces, nonce 0 should be accepted again.
        validator.reset(state, NativeNonceStore::default());

        let tx0_again = signed_native_tx(&sk, &pk_bytes, 0);
        let result = validator.validate_tx(&tx0_again).await.unwrap();
        assert_eq!(result.nonce, 0);
    }

    #[tokio::test]
    async fn reset_preserves_finalized_nonces() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);

        let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
        validator.validate_tx(&tx0).await.unwrap();

        // Simulate finalization: pass the committed nonce store.
        let committed_nonces = validator.native_nonces.clone();
        validator.reset(state, committed_nonces);

        // Nonce 0 should now be rejected (already finalized).
        let tx0_replay = signed_native_tx(&sk, &pk_bytes, 0);
        let err = validator.validate_tx(&tx0_replay).await.unwrap_err();
        assert!(matches!(err, ExecutionError::NonceMismatch { .. }));

        // Nonce 1 should be accepted.
        let tx1 = signed_native_tx(&sk, &pk_bytes, 1);
        let result = validator.validate_tx(&tx1).await.unwrap();
        assert_eq!(result.nonce, 1);
    }

    #[tokio::test]
    async fn reset_recheck_preserves_pending_native_nonce_reservations() {
        let (key, public) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);
        let first = signed_native_tx(&key, &public, 0);
        validator.validate_tx(&first).await.unwrap();
        let finalized_nonces = validator.native_nonces.clone();
        let pending = signed_native_tx(&key, &public, 1);
        validator.validate_tx(&pending).await.unwrap();

        // The first request finalized; the second remains in the pending pool.
        validator.reset(state, finalized_nonces);
        assert!(matches!(
            validator.recheck_pending_tx(&first).await,
            Err(ExecutionError::NonceMismatch {
                expected: 1,
                got: 0,
                ..
            })
        ));
        validator.recheck_pending_tx(&pending).await.unwrap();
        let next = signed_native_tx(&key, &public, 2);
        assert_eq!(validator.validate_tx(&next).await.unwrap().nonce, 2);

        let mut conflicting = NativeTx::decode_wire(&pending).unwrap();
        conflicting.calldata = Bytes::from_static(b"different request");
        conflicting.signature =
            FixedBytes::from_slice(&bls::sign(&key, &conflicting.signing_data()).unwrap());
        assert!(matches!(
            validator.validate_tx(&conflicting.encode_wire()).await,
            Err(ExecutionError::NonceMismatch {
                expected: 3,
                got: 1,
                ..
            })
        ));
        let following = signed_native_tx(&key, &public, 3);
        assert_eq!(validator.validate_tx(&following).await.unwrap().nonce, 3);
    }

    #[test]
    fn rejected_native_request_admits_after_peer_catches_up() {
        let (key, public) = test_bls_keypair();
        let predecessor = signed_native_tx(&key, &public, 0);
        let predecessor =
            MempoolValidator::<MockStateDb>::pre_validate_native(CHAIN_ID, &predecessor).unwrap();
        let request = signed_native_tx(&key, &public, 1);
        let request =
            MempoolValidator::<MockStateDb>::pre_validate_native(CHAIN_ID, &request).unwrap();
        let state = MockStateDb::new();
        let mut source = MempoolValidator::new(state.clone(), test_config(), 0);
        source.admit_native(&predecessor).unwrap();
        let finalized_nonces = source.native_nonces.clone();
        source.reset(state.clone(), finalized_nonces.clone());
        source.admit_native(&request).unwrap();

        let mut peer = MempoolValidator::new(state.clone(), test_config(), 0);
        assert!(matches!(
            peer.admit_native(&request),
            Err(ExecutionError::NonceMismatch {
                expected: 0,
                got: 1,
                ..
            })
        ));
        peer.admit_native(&predecessor).unwrap();
        peer.reset(state, finalized_nonces);
        assert_eq!(peer.admit_native(&request).unwrap().nonce, 1);
        assert!(matches!(
            peer.admit_native(&request),
            Err(ExecutionError::NonceMismatch {
                expected: 2,
                got: 1,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn reset_clears_evm_nonce_state() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 * 10);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        validator.validate_tx(&tx0).await.unwrap();

        // After reset, nonce 0 should be accepted again.
        validator.reset(state, NativeNonceStore::default());

        let tx0_again = signed_evm_tx(&signer, 0);
        let result = validator.validate_tx(&tx0_again).await.unwrap();
        assert_eq!(result.nonce, 0);
    }

    // -- Format detection --

    #[tokio::test]
    async fn format_detection_native() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx = signed_native_tx(&sk, &pk_bytes, 0);
        assert_eq!(tx[0], 0x45);
        let result = validator.validate_tx(&tx).await.unwrap();
        assert!(result.is_native);
    }

    #[tokio::test]
    async fn format_detection_evm() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        // 0x02 is EIP-1559 type prefix, but garbage RLP → TxDecode.
        // This still proves format detection routes to EVM path.
        let err = validator.validate_tx(&[0x02, 0xFF]).await.unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }
}
