//! Anchors: the newest finalized revision of other deployments, recorded in order.
//!
//! A submission carries a deployment's consensus key and the finality
//! artifacts of one of its revisions. The revision is recorded only when its
//! certificate verifies against that key, it is higher than the deployment's
//! latest anchor, and its term is not lower. The record is kept in the
//! identity partition under the deployment's identifier, which is derived
//! from the key, so nobody can record revisions under another deployment's
//! identifier.

/// Solidity ABI interface for the anchor precompile.
pub mod abi;
mod error;
mod record;
#[cfg(test)]
mod tests;

pub use error::AnchorError;
pub use record::{
    AnchorRecord, MAX_ANCHOR_RECORD_BYTES, anchor_key, decode_consensus_key, deployment_id,
};

use vera_domain::{FinalizedArtifacts, verify_finalized_artifacts};

use super::VeraModule;
use crate::kv_store::ModuleKvStore as _;
use crate::types::BlockExecCtx;

/// Largest combined finality artifacts an anchor accepts, in bytes.
pub const MAX_ANCHOR_ARTIFACT_BYTES: usize = 256 << 10;

/// A deployment's key and the finality artifacts of the revision to anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSubmission {
    /// Canonical encoding of the deployment's consensus key.
    pub consensus_key: Vec<u8>,
    /// The revision and its finalization.
    pub artifacts: FinalizedArtifacts,
}

/// What an accepted submission did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchored {
    /// The deployment's latest anchor after the submission.
    pub record: AnchorRecord,
    /// Whether the submission recorded a new anchor; resubmitting the latest one does not.
    pub recorded: bool,
}

impl VeraModule {
    /// Record a finalized revision of another deployment as its latest anchor.
    pub fn anchor_revision(
        &mut self,
        block_ctx: &BlockExecCtx,
        submission: &AnchorSubmission,
    ) -> Result<Anchored, AnchorError> {
        if submission.artifacts.encoded_len() > MAX_ANCHOR_ARTIFACT_BYTES {
            return Err(AnchorError::TooLarge);
        }
        let key = decode_consensus_key(&submission.consensus_key)?;
        let (block, block_hash) = verify_finalized_artifacts(&submission.artifacts, &key)?;
        let deployment = deployment_id(&key);
        let latest = self.latest_anchor(&deployment)?;
        if let Some(latest) = &latest {
            if latest.height == block.height && latest.block_hash == block_hash {
                return Ok(Anchored {
                    record: latest.clone(),
                    recorded: false,
                });
            }
            if block.height <= latest.height {
                return Err(AnchorError::NotNewer {
                    latest: latest.height,
                    height: block.height,
                });
            }
            if block.term < latest.term {
                return Err(AnchorError::LowerTerm {
                    latest: latest.term,
                    term: block.term,
                });
            }
        }
        let record = AnchorRecord {
            deployment,
            consensus_key: submission.consensus_key.clone().into(),
            sequence: latest.map_or(1, |latest| latest.sequence + 1),
            height: block.height,
            block_hash,
            term: block.term,
            timestamp: block.timestamp,
            module_state_root: block.module_state_root,
            anchored_at: block_ctx.timestamp.block_height,
        };
        self.store.put(&anchor_key(&deployment), record.encode());
        Ok(Anchored {
            record,
            recorded: true,
        })
    }

    /// The latest anchor of `deployment`, if it has one.
    pub fn latest_anchor(
        &self,
        deployment: &alloy_primitives::B256,
    ) -> Result<Option<AnchorRecord>, AnchorError> {
        self.store
            .get(&anchor_key(deployment))
            .map(|bytes| AnchorRecord::decode(deployment, &bytes))
            .transpose()
    }
}
