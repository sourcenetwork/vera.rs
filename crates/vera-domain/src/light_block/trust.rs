//! How a verifier establishes that a light block's revision is finalized.

use commonware_cryptography::bls12381::primitives::group::G2;

use super::{LightBlock, LightBlockError, verify_finalized_block};
use crate::Block;

/// Establishes the finality of the revision a light block carries.
///
/// A consensus key verifies the certificate of every light block it is shown.
/// A verifier that has checked a revision before may answer from that check.
pub trait FinalityTrust {
    /// The revision's canonical block, once its finality is established.
    fn finalized_block(&self, light: &LightBlock) -> Result<Block, LightBlockError>;
}

// Named by its group so that implementations for other types do not overlap
// an unnormalized `ConsensusPublicKey` projection.
impl FinalityTrust for G2 {
    fn finalized_block(&self, light: &LightBlock) -> Result<Block, LightBlockError> {
        verify_finalized_block(light, self)
    }
}
