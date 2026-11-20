//! Canonical finality artifacts as bytes, without the light block's JSON header.

use super::{LIGHT_BLOCK_MAX_ARTIFACT_BYTES, LIGHT_BLOCK_MAX_DESCENDANTS, LightBlockError};

/// The canonical block, its descendants up to the certified block, the
/// finalization certificate and the epoch material, as a [`super::LightBlock`]
/// carries them in hex.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinalizedArtifacts {
    /// Canonical encoded block.
    pub block: Vec<u8>,
    /// Canonical encoded descendants in ascending height order.
    pub descendants: Vec<Vec<u8>>,
    /// Canonical encoded finalization of the last block.
    pub finalization: Vec<u8>,
    /// Canonical encoded epoch material of the last block.
    pub epoch_material: Vec<u8>,
}

impl FinalizedArtifacts {
    /// Combined length of every artifact.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.descendants.iter().map(Vec::len).fold(
            self.block.len() + self.finalization.len() + self.epoch_material.len(),
            usize::saturating_add,
        )
    }

    /// Reject excessive descendant count or combined size.
    pub fn check_limits(&self) -> Result<(), LightBlockError> {
        if self.descendants.len() > LIGHT_BLOCK_MAX_DESCENDANTS
            || self.encoded_len() > LIGHT_BLOCK_MAX_ARTIFACT_BYTES
        {
            return Err(LightBlockError::LimitExceeded);
        }
        Ok(())
    }
}
