//! Opening a deployment on a device that follows it as a backup.

use std::net::SocketAddr;

use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use vera_config::NodeConfig;
use vera_genesis::VeraGenesis;

use super::{SoloError, SoloGenesis, adopt::store_record, check_identity, record::decode};
use crate::PeerSet;

/// Key material a validator keeps in its directory, which a backup must not hold.
const KEY_FILES: [&str; 2] = ["validator.key", "secrets.json"];

/// Open the deployment `record` describes in `config.data_dir` without any of
/// its key material, to follow the validator listening at `active`.
///
/// The record is stored if the directory is empty. A directory that keeps a
/// validator's key or share is refused: a backup holds neither.
pub(crate) fn follow_solo(
    config: &NodeConfig,
    identity: &SoloGenesis,
    record: &[u8],
    active: SocketAddr,
) -> Result<(VeraGenesis, PeerSet), SoloError> {
    let directory = &config.data_dir;
    let genesis = decode(record)?;
    let validator = validator(&genesis)?;
    check_identity(&genesis, identity, &validator)?;
    genesis
        .validate_timestamp()
        .map_err(|error| SoloError::Genesis(error.to_string()))?;
    if KEY_FILES
        .iter()
        .any(|name| directory.join(name).symlink_metadata().is_ok())
    {
        return Err(SoloError::Mismatch(
            "the directory keeps a validator's key material",
        ));
    }
    store_record(directory, identity, &validator, &genesis, record)?;
    Ok((
        genesis,
        PeerSet {
            participants: vec![validator.clone()],
            bootstrappers: vec![(validator, active)],
        },
    ))
}

/// The only validator of a solo genesis, which is also the only member of its epoch-0 sharing.
fn validator(genesis: &VeraGenesis) -> Result<PublicKey, SoloError> {
    let [only] = genesis.validators.as_slice() else {
        return Err(SoloError::Genesis(
            "the deployment has more than one validator".into(),
        ));
    };
    let key = hex::decode(&only.consensus_pubkey)
        .ok()
        .and_then(|bytes| PublicKey::decode(commonware_codec::Copying(bytes.as_slice())).ok())
        .ok_or_else(|| SoloError::Genesis("validator key does not decode".into()))?;
    let players = genesis
        .decode_epoch_info()
        .map_err(|error| SoloError::Genesis(error.to_string()))?
        .ok_or_else(|| SoloError::Genesis("missing epoch information".into()))?
        .output
        .players()
        .clone();
    if players.len() != 1 || players.position(&key).is_none() {
        return Err(SoloError::Genesis(
            "the validator does not hold the deployment's only share".into(),
        ));
    }
    Ok(key)
}

#[cfg(test)]
#[path = "follow_tests.rs"]
mod tests;
