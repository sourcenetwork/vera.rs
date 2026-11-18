//! Opening and exporting a deployment whose key material the host holds.

use std::path::Path;

use commonware_cryptography::ed25519::PublicKey;
use vera_config::NodeConfig;
use vera_genesis::VeraGenesis;

use super::{
    GENESIS_FILE, PENDING_FILE, SoloDeployment, SoloError, SoloGenesis, SoloKeys, check_identity,
    io, listen_address, lone_peer,
};
use crate::{FileSecretStore, PeerSet};

/// What a directory holds once a node has run in it, or keeps its keys in it.
const VALIDATOR_STATE: [&str; 5] = [
    "validator.key",
    "secrets.json",
    "native-genesis.bin",
    "history",
    "commonware",
];

/// Open `deployment` in `config.data_dir`, storing its genesis if the directory is empty.
///
/// The record and the share are checked before anything is stored, and the key
/// material is not stored at all. A directory that already holds this
/// deployment is left as it is.
pub(crate) fn adopt_solo(
    config: &NodeConfig,
    identity: &SoloGenesis,
    deployment: &SoloDeployment,
) -> Result<(VeraGenesis, PeerSet), SoloError> {
    let directory = &config.data_dir;
    let local = deployment.keys().public_key();
    let listen = listen_address(config)?;
    let genesis = deployment.genesis()?;
    check_identity(&genesis, identity, &local)?;
    check_share(&genesis, deployment.keys())?;
    genesis
        .validate_timestamp()
        .map_err(|error| SoloError::Genesis(error.to_string()))?;
    store_record(directory, identity, &local, &genesis, deployment.record())?;
    Ok((genesis, lone_peer(local, listen)))
}

/// Store `record` in an empty `directory`, or accept the same record already there.
pub(super) fn store_record(
    directory: &Path,
    identity: &SoloGenesis,
    local: &PublicKey,
    genesis: &VeraGenesis,
    record: &[u8],
) -> Result<(), SoloError> {
    let stored = directory.join(GENESIS_FILE);
    if stored.exists() {
        let held =
            VeraGenesis::load(&stored).map_err(|error| SoloError::Genesis(error.to_string()))?;
        check_identity(&held, identity, local)?;
        if json(&held)? != json(genesis)? {
            return Err(SoloError::Mismatch("genesis record"));
        }
    } else {
        if VALIDATOR_STATE
            .iter()
            .any(|name| directory.join(name).symlink_metadata().is_ok())
        {
            return Err(SoloError::Incomplete(
                "validator state exists without a genesis",
            ));
        }
        std::fs::create_dir_all(directory).map_err(|source| io(directory, source))?;
        let pending = directory.join(PENDING_FILE);
        vera_cli::write_durable(&pending, record).map_err(|source| io(&pending, source))?;
        #[cfg(feature = "fault-injection")]
        crate::crash::point(directory, "solo-record");
        std::fs::rename(&pending, &stored).map_err(|source| io(&stored, source))?;
        vera_cli::sync_parent(&stored).map_err(|source| io(directory, source))?;
    }
    Ok(())
}

/// The deployment stored in `directory` with the key material kept in its files.
pub(crate) fn export_solo(directory: &Path) -> Result<SoloDeployment, SoloError> {
    let stored = directory.join(GENESIS_FILE);
    let record = std::fs::read(&stored).map_err(|source| io(&stored, source))?;
    let validator_key = NodeConfig {
        data_dir: directory.to_path_buf(),
        ..NodeConfig::default()
    }
    .validator_key()?;
    let share = FileSecretStore::load(directory.join("secrets.json"))
        .map_err(|error| SoloError::Share(format!("{error:#}")))?
        .latest_share()
        .ok_or(SoloError::Incomplete("consensus share is missing"))?;
    let deployment = SoloDeployment::new(record, SoloKeys::new(validator_key, share));
    check_share(&deployment.genesis()?, deployment.keys())?;
    Ok(deployment)
}

/// Refuse a share other than the only one of the genesis's epoch-0 sharing.
///
/// A committee of one reshares to itself with a constant polynomial, so this is
/// also the share of every later epoch the lone validator runs.
fn check_share(genesis: &VeraGenesis, keys: &SoloKeys) -> Result<(), SoloError> {
    let output = genesis
        .decode_epoch_info()
        .map_err(|error| SoloError::Genesis(error.to_string()))?
        .ok_or_else(|| SoloError::Genesis("missing epoch information".into()))?
        .output;
    if output.players().len() != 1 {
        return Err(SoloError::Genesis(
            "the deployment has more than one validator".into(),
        ));
    }
    crate::provider::signer_scheme(
        &keys.public_key(),
        output.players().clone(),
        output.public().clone(),
        keys.consensus_share(),
    )
    .map(|_| ())
    .map_err(|_| SoloError::ShareMismatch)
}

fn json(genesis: &VeraGenesis) -> Result<serde_json::Value, SoloError> {
    serde_json::to_value(genesis).map_err(|error| SoloError::Genesis(error.to_string()))
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
