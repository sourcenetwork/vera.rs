//! A validator's network address, changed under its consensus key.

use alloy_primitives::{Address, B256};
use alloy_sol_types::SolCall;
use ed25519_dalek::Signer as _;
use vera_modules::validator_registry::{abi::IValidatorRegistry, address_update_digest};

use crate::bls_signer::BlsSigner;
use crate::client::{VALIDATOR_REGISTRY_ADDRESS, VeraClient};
use crate::error::ClientError;
use crate::types::TransactionReceipt;

/// A validator's signed request to be dialed at a new address.
///
/// The validator's Ed25519 consensus key signs it; any native signer may
/// submit it, and it applies once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorAddressUpdate {
    /// The validator's registry address.
    pub validator: Address,
    /// The socket address peers dial from now on.
    pub p2p_address: String,
    /// The validator record's `address_sequence` when the update applies.
    pub sequence: u64,
    /// Ed25519 signature of the consensus key over the update's digest.
    pub signature: [u8; 64],
}

impl ValidatorAddressUpdate {
    /// Sign an update with the validator's consensus key.
    ///
    /// `consensus_key` is the 32-byte Ed25519 secret the validator's key file
    /// holds, `genesis_id` the deployment's genesis record identifier, and
    /// `admission` and `sequence` the validator record's current values. A
    /// signature made under one admission does not apply to a record created
    /// by a later one.
    #[must_use]
    pub fn sign(
        consensus_key: &[u8; 32],
        genesis_id: B256,
        validator: Address,
        admission: u64,
        sequence: u64,
        p2p_address: &str,
    ) -> Self {
        let digest =
            address_update_digest(&genesis_id.0, validator, admission, sequence, p2p_address);
        Self {
            validator,
            p2p_address: p2p_address.to_owned(),
            sequence,
            signature: ed25519_dalek::SigningKey::from_bytes(consensus_key)
                .sign(&digest)
                .to_bytes(),
        }
    }

    /// The registry call that applies this update.
    #[must_use]
    pub fn calldata(&self) -> Vec<u8> {
        IValidatorRegistry::updateP2PAddressCall {
            validator: self.validator,
            p2pAddr: self.p2p_address.clone(),
            sequence: self.sequence,
            signature: self.signature.to_vec().into(),
        }
        .abi_encode()
    }
}

impl VeraClient {
    /// Submit a validator's signed address update as `signer`.
    pub async fn native_update_validator_address(
        &self,
        signer: &BlsSigner,
        update: &ValidatorAddressUpdate,
    ) -> Result<TransactionReceipt, ClientError> {
        self.send_native_precompile_tx(signer, VALIDATOR_REGISTRY_ADDRESS, update.calldata().into())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_is_the_consensus_keys_over_the_registry_digest() {
        let secret = [5; 32];
        let update = ValidatorAddressUpdate::sign(
            &secret,
            B256::repeat_byte(7),
            Address::repeat_byte(1),
            2,
            3,
            "127.0.0.1:30300",
        );
        let public = ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes();
        let signer = vera_crypto::actor::ed25519_did(&public).unwrap();
        let digest =
            address_update_digest(&[7; 32], Address::repeat_byte(1), 2, 3, "127.0.0.1:30300");
        vera_crypto::actor::verify_digest(&signer, &digest, &update.signature).unwrap();
        let call =
            IValidatorRegistry::updateP2PAddressCall::abi_decode(&update.calldata()).unwrap();
        assert_eq!((call.sequence, call.signature.len()), (3, 64));
    }
}
