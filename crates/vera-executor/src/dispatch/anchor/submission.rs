//! An anchor submission and its verification against the anchored deployment's key.
//!
//! The identity module records anchors without consensus types; finality and
//! ancestry are verified here, before the module sees the revision.

use alloy_primitives::B256;
use commonware_codec::{DecodeExt as _, FixedSize as _};
use vera_domain::{
    AncestryProof, Block, BlockId, ConsensusPublicKey, FinalizedArtifacts, LightBlockError,
    verify_finalized_artifacts,
};
use vera_modules::vera::anchors::{
    AnchorError, CONSENSUS_KEY_BYTES, MAX_ANCHOR_ARTIFACT_BYTES, VerifiedRevision,
};

const _: () = assert!(ConsensusPublicKey::SIZE == CONSENSUS_KEY_BYTES);

/// A deployment and the finality artifacts of one of its revisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AnchorSubmission {
    /// The deployment's identifier.
    pub(crate) deployment: B256,
    /// The revision and its finalization.
    pub(crate) artifacts: FinalizedArtifacts,
}

/// A verified submission: the finalized block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedSubmission {
    /// The finalized block.
    pub(crate) block: Block,
    /// The block's identifier.
    pub(crate) block_hash: B256,
}

/// Why an anchor submission is refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AnchorRefusal {
    /// The identity module refused the submission or its stored record.
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// The revision is not finalized under the consensus key.
    #[error("revision is not finalized under the deployment's key: {0}")]
    Finality(#[from] LightBlockError),
}

impl AnchorSubmission {
    /// Check the size and verify the revision's finalization under
    /// `consensus_key`, the key the deployment is registered with.
    pub(crate) fn verify(&self, consensus_key: &[u8]) -> Result<VerifiedSubmission, AnchorRefusal> {
        if self.artifacts.encoded_len() > MAX_ANCHOR_ARTIFACT_BYTES {
            return Err(AnchorError::TooLarge.into());
        }
        let key = ConsensusPublicKey::decode(commonware_codec::Copying(consensus_key))
            .map_err(|_| AnchorError::InvalidConsensusKey)?;
        let (block, block_hash) = verify_finalized_artifacts(&self.artifacts, &key)?;
        Ok(VerifiedSubmission { block, block_hash })
    }
}

impl VerifiedSubmission {
    /// The revision to record. Its ancestor is the block `ancestor` at
    /// `height` when `proof` shows that block to be an ancestor of the
    /// finalized one, and absent otherwise.
    pub(crate) fn revision(&self, height: u64, ancestor: B256, proof: &[u8]) -> VerifiedRevision {
        let proven = AncestryProof::decode(proof)
            .is_ok_and(|proof| self.block.has_ancestor(height, &BlockId(ancestor), &proof));
        VerifiedRevision {
            height: self.block.height,
            block_hash: self.block_hash,
            term: self.block.term,
            timestamp: self.block.timestamp,
            module_state_root: self.block.module_state_root,
            ancestor: proven.then_some((height, ancestor)),
        }
    }
}
