//! A deployment's genesis record, read without its key material.

use vera_genesis::VeraGenesis;

use super::{SoloError, SoloGenesis};

/// The genesis a record describes.
pub(super) fn decode(record: &[u8]) -> Result<VeraGenesis, SoloError> {
    serde_json::from_slice(record).map_err(|error| SoloError::Genesis(error.to_string()))
}

/// The identity a genesis describes.
pub(super) fn identity(genesis: VeraGenesis) -> Result<SoloGenesis, SoloError> {
    Ok(SoloGenesis {
        chain_id: genesis.chain_id,
        operators: genesis
            .operators
            .ok_or_else(|| SoloError::Genesis("missing operator policy".into()))?,
        timestamp: genesis.timestamp,
        policies: genesis.placed_policies,
    })
}

/// The identity of the deployment `record` describes.
pub(crate) fn record_identity(record: &[u8]) -> Result<SoloGenesis, SoloError> {
    identity(decode(record)?)
}
