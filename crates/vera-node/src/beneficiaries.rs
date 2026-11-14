//! Block beneficiaries of the genesis validators.

use alloy_primitives::Address;
use commonware_codec::ReadExt as _;
use vera_domain::PublicKey;
use vera_genesis::VeraGenesis;

/// Pair each genesis validator's consensus key with its registered address.
///
/// The pairs enter block execution, so they come from the genesis document
/// alone: every validator derives the same mapping whatever its local files say.
pub(crate) fn from_genesis(genesis: &VeraGenesis) -> anyhow::Result<Vec<(PublicKey, Address)>> {
    let addresses = genesis.to_genesis_state()?.participant_addresses;
    genesis
        .validators
        .iter()
        .zip(addresses)
        .map(|(validator, address)| {
            let bytes = hex::decode(&validator.consensus_pubkey)?;
            let key = PublicKey::read(&mut commonware_codec::Copying(bytes.as_slice()))
                .map_err(|error| anyhow::anyhow!("genesis consensus key: {error}"))?;
            Ok((key, address))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use vera_genesis::ValidatorConfig;

    fn entry(seed: u64, address: Address) -> (PublicKey, ValidatorConfig) {
        let key = ed25519::PrivateKey::from_seed(seed).public_key();
        let validator = ValidatorConfig {
            evm_address: format!("{address:?}"),
            consensus_pubkey: hex::encode(commonware_codec::Encode::encode(&key)),
            p2p_address: "127.0.0.1:3000".into(),
        };
        (key, validator)
    }

    #[test]
    fn each_key_maps_to_the_address_registered_beside_it() {
        let (first_key, first) = entry(1, Address::repeat_byte(0x11));
        let (second_key, second) = entry(2, Address::repeat_byte(0x22));
        let mut genesis = VeraGenesis::devnet();
        genesis.validators = vec![second, first];

        assert_eq!(
            from_genesis(&genesis).unwrap(),
            vec![
                (second_key, Address::repeat_byte(0x22)),
                (first_key, Address::repeat_byte(0x11)),
            ]
        );
    }

    #[test]
    fn a_genesis_without_validators_has_no_beneficiaries() {
        let mut genesis = VeraGenesis::devnet();
        genesis.validators.clear();
        assert!(from_genesis(&genesis).unwrap().is_empty());
    }
}
