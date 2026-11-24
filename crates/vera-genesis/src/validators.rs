//! Genesis members of the validator registry.

use std::{collections::HashSet, str::FromStr};

use alloy_evm::revm::primitives::Address;
use commonware_codec::ReadExt as _;
use vera_modules::validator_registry::validate_p2p_address;

use crate::{ValidatorConfig, VeraGenesisError};

/// The registry's genesis members: address, consensus key and network
/// address. Addresses and consensus keys are distinct and well formed.
pub(crate) fn registry_members(
    validators: &[ValidatorConfig],
) -> Result<Vec<(Address, [u8; 32], String)>, VeraGenesisError> {
    let mut addresses = HashSet::new();
    let mut keys = HashSet::new();
    let mut members = Vec::with_capacity(validators.len());
    for validator in validators {
        let address = Address::from_str(&validator.evm_address)
            .map_err(|e| VeraGenesisError::Parse(format!("invalid validator address: {e}")))?;
        if address == Address::ZERO {
            return Err(VeraGenesisError::Parse(
                "validator address cannot be zero".into(),
            ));
        }
        if !addresses.insert(address) {
            return Err(VeraGenesisError::Parse(format!(
                "duplicate validator address: {address}"
            )));
        }
        let consensus: [u8; 32] = hex::decode(&validator.consensus_pubkey)
            .map_err(|e| VeraGenesisError::Parse(format!("invalid consensus pubkey: {e}")))?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                VeraGenesisError::Parse(format!(
                    "consensus pubkey must be 32 bytes, got {}",
                    bytes.len()
                ))
            })?;
        if consensus == [0u8; 32] {
            return Err(VeraGenesisError::Parse(
                "consensus pubkey cannot be all zeros".into(),
            ));
        }
        vera_domain::PublicKey::read(&mut commonware_codec::Copying(consensus.as_slice()))
            .map_err(|error| {
                VeraGenesisError::Parse(format!("invalid consensus pubkey: {error}"))
            })?;
        // The executor treats a roster with a repeated key as unreadable state.
        if !keys.insert(consensus) {
            return Err(VeraGenesisError::Parse(format!(
                "duplicate consensus pubkey: {}",
                validator.consensus_pubkey
            )));
        }
        validate_p2p_address(&validator.p2p_address).map_err(|error| {
            VeraGenesisError::Parse(format!(
                "invalid validator p2p address '{}': {error}",
                validator.p2p_address
            ))
        })?;
        members.push((address, consensus, validator.p2p_address.clone()));
    }
    Ok(members)
}
