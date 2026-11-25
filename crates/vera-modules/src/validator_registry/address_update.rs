//! A member's network address, changed under its consensus key.

use alloy_primitives::{Address, keccak256};

use super::{error::ValidatorRegistryError, validate_p2p_address};
use crate::vera::VeraModule;

const DOMAIN: &[u8] = b"vera/registry/p2p-address/v1";

/// The digest a member's consensus key signs to move it to `p2p_address`.
///
/// It binds the deployment's genesis record, the member, the admission its
/// record was created by, the sequence the record expects and the new address.
pub fn address_update_digest(
    genesis_id: &[u8; 32],
    validator: Address,
    admission: u64,
    sequence: u64,
    p2p_address: &str,
) -> [u8; 32] {
    keccak256(
        [
            DOMAIN,
            genesis_id,
            validator.as_slice(),
            &admission.to_be_bytes(),
            &sequence.to_be_bytes(),
            p2p_address.as_bytes(),
        ]
        .concat(),
    )
    .0
}

impl VeraModule {
    /// Replace a member's network address.
    ///
    /// `signature` is the Ed25519 signature of the member's consensus key over
    /// [`address_update_digest`]. Whoever submits it needs no authority of its
    /// own. `sequence` lets each signature apply once, and the record's
    /// admission keeps a signature made before the member was removed from
    /// applying after it is admitted again.
    pub fn update_p2p_address(
        &mut self,
        genesis_id: &[u8; 32],
        validator: Address,
        p2p_address: &str,
        sequence: u64,
        signature: &[u8],
    ) -> Result<(), ValidatorRegistryError> {
        let unauthorized = |reason: &str| ValidatorRegistryError::Unauthorized(reason.into());
        if *genesis_id == [0; 32] {
            return Err(unauthorized("deployment has no genesis record"));
        }
        validate_p2p_address(p2p_address)?;
        let mut member = self
            .registry_member(validator)?
            .ok_or_else(|| ValidatorRegistryError::ValidatorNotFound(format!("{validator:?}")))?;
        if sequence != member.address_sequence {
            return Err(unauthorized("address update sequence is not the next one"));
        }
        let signer = vera_crypto::actor::ed25519_did(&member.consensus_key)
            .map_err(|_| ValidatorRegistryError::Corrupt("invalid consensus key".into()))?;
        let digest = address_update_digest(
            genesis_id,
            validator,
            member.admission,
            sequence,
            p2p_address,
        );
        vera_crypto::actor::verify_digest(&signer, &digest, signature)
            .map_err(|_| unauthorized("signature is not the validator's consensus key's"))?;
        member.p2p_address = p2p_address.to_owned();
        member.address_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| unauthorized("address update sequence is exhausted"))?;
        self.put_member(validator, &member);
        Ok(())
    }
}
