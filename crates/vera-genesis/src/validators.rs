//! Genesis storage of the validator registry account.

use std::{collections::HashSet, str::FromStr};

use alloy_evm::revm::primitives::{Address, U256};
use commonware_codec::ReadExt as _;
use vera_modules::validator_registry::layout::{
    MAX_P2P_ADDRESS_LEN, SLOT_POLICY_ID, SLOT_VALIDATOR_COUNT, SLOT_VALIDATORS_ARRAY_BASE,
    SLOT_VALIDATORS_MAPPING_BASE, address_to_padded_u256, array_element_slot, mapping_slot,
    pack_address_active,
};

use crate::{ValidatorConfig, VeraGenesisError};

/// EVM `INVALID` opcode: marks the account as holding code and reverts if run.
pub(crate) const PRECOMPILE_SENTINEL_BYTECODE: &[u8] = &[0xfe];

fn validate_genesis_p2p_address(addr: &str) -> Result<(), VeraGenesisError> {
    if addr.is_empty() {
        return Err(VeraGenesisError::Parse(
            "validator p2p address is empty".into(),
        ));
    }
    if addr.len() > MAX_P2P_ADDRESS_LEN {
        return Err(VeraGenesisError::Parse(format!(
            "validator p2p address exceeds {MAX_P2P_ADDRESS_LEN} bytes: {addr}"
        )));
    }
    addr.parse::<std::net::SocketAddr>().map_err(|e| {
        VeraGenesisError::Parse(format!("invalid validator p2p address '{addr}': {e}"))
    })?;
    Ok(())
}

pub(crate) fn validator_storage_entries(
    validators: &[ValidatorConfig],
) -> Result<Vec<(U256, U256)>, VeraGenesisError> {
    let mut seen = HashSet::new();
    let mut seen_keys = HashSet::new();
    for v in validators {
        let addr = Address::from_str(&v.evm_address)
            .map_err(|e| VeraGenesisError::Parse(format!("invalid validator address: {e}")))?;
        if !seen.insert(addr) {
            return Err(VeraGenesisError::Parse(format!(
                "duplicate validator address: {addr}"
            )));
        }
    }

    let mut entries = Vec::new();

    entries.push((SLOT_POLICY_ID, U256::ZERO));
    entries.push((SLOT_VALIDATOR_COUNT, U256::from(validators.len())));

    for (i, v) in validators.iter().enumerate() {
        let addr = Address::from_str(&v.evm_address)
            .map_err(|e| VeraGenesisError::Parse(format!("invalid validator address: {e}")))?;
        if addr == Address::ZERO {
            return Err(VeraGenesisError::Parse(
                "validator address cannot be zero".into(),
            ));
        }
        let consensus_bytes = hex::decode(&v.consensus_pubkey)
            .map_err(|e| VeraGenesisError::Parse(format!("invalid consensus pubkey: {e}")))?;
        if consensus_bytes.len() != 32 {
            return Err(VeraGenesisError::Parse(format!(
                "consensus pubkey must be 32 bytes, got {}",
                consensus_bytes.len()
            )));
        }
        let mut consensus: [u8; 32] = [0u8; 32];
        consensus.copy_from_slice(&consensus_bytes);
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
        if !seen_keys.insert(consensus) {
            return Err(VeraGenesisError::Parse(format!(
                "duplicate consensus pubkey: {}",
                v.consensus_pubkey
            )));
        }
        validate_genesis_p2p_address(&v.p2p_address)?;

        let addr_slot = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, i as u64);
        entries.push((addr_slot, address_to_padded_u256(addr)));

        let entry_base = mapping_slot(addr, SLOT_VALIDATORS_MAPPING_BASE);
        entries.push((entry_base, pack_address_active(addr, true)));
        entries.push((
            entry_base.wrapping_add(U256::from(1)),
            U256::from_be_bytes(consensus),
        ));
        entries.push((entry_base.wrapping_add(U256::from(2)), U256::from(i)));
        let p2p_bytes = v.p2p_address.as_bytes();
        entries.push((
            entry_base.wrapping_add(U256::from(3)),
            U256::from(p2p_bytes.len()),
        ));
        let mut padded = [0u8; 32];
        padded[..p2p_bytes.len()].copy_from_slice(p2p_bytes);
        entries.push((
            entry_base.wrapping_add(U256::from(4)),
            U256::from_be_bytes(padded),
        ));
    }

    Ok(entries)
}
