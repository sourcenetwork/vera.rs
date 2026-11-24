//! An anchor submission and its verification against the anchored deployment's key.
//!
//! The identity module records anchors without consensus types; finality is
//! verified here, before the module sees the revision.

use commonware_codec::{DecodeExt as _, Encode as _, FixedSize as _};
use vera_domain::{
    ConsensusPublicKey, FinalizedArtifacts, LightBlockError, verify_finalized_artifacts,
};
use vera_modules::vera::anchors::{
    AnchorError, CONSENSUS_KEY_BYTES, MAX_ANCHOR_ARTIFACT_BYTES, VerifiedRevision,
};

const _: () = assert!(ConsensusPublicKey::SIZE == CONSENSUS_KEY_BYTES);

/// A deployment's key and the finality artifacts of the revision to anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AnchorSubmission {
    /// Encoding of the deployment's consensus key.
    pub(crate) consensus_key: Vec<u8>,
    /// The revision and its finalization.
    pub(crate) artifacts: FinalizedArtifacts,
}

/// A verified submission: the key's canonical encoding and the revision to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedSubmission {
    /// Canonical encoding of the deployment's consensus key.
    pub(crate) consensus_key: Vec<u8>,
    /// The finalized revision.
    pub(crate) revision: VerifiedRevision,
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
    /// Check the size, decode the key and verify the revision's finalization under it.
    pub(crate) fn verify(&self) -> Result<VerifiedSubmission, AnchorRefusal> {
        if self.artifacts.encoded_len() > MAX_ANCHOR_ARTIFACT_BYTES {
            return Err(AnchorError::TooLarge.into());
        }
        let key = ConsensusPublicKey::decode(commonware_codec::Copying(&self.consensus_key[..]))
            .map_err(|_| AnchorError::InvalidConsensusKey)?;
        let (block, block_hash) = verify_finalized_artifacts(&self.artifacts, &key)?;
        Ok(VerifiedSubmission {
            consensus_key: key.encode().to_vec(),
            revision: VerifiedRevision {
                height: block.height,
                block_hash,
                term: block.term,
                timestamp: block.timestamp,
                module_state_root: block.module_state_root,
            },
        })
    }
}
