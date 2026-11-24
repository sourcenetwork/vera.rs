//! Anchors: the finalized revisions of other deployments, recorded as one chain each.
//!
//! A submission carries a deployment's consensus key, the finality artifacts
//! of one of its revisions and a proof that the deployment's latest anchor is
//! an ancestor of it. The executor verifies the certificate against that key
//! and the proof against the block; this module then records the revision
//! when it is higher than the latest anchor, descends from it, and its term
//! is not lower. A finalized block that does not descend from the latest
//! anchor is recorded as a fork. Every anchor stays in the deployment's
//! history, in sequence order. Records are kept in the identity partition
//! under the deployment's identifier, which is derived from the key, so
//! nobody can record revisions under another deployment's identifier.

/// Solidity ABI interface for the anchor precompile.
pub mod abi;
mod error;
mod fork;
mod history;
mod record;
mod revision;
#[cfg(test)]
mod tests;

pub use error::AnchorError;
pub use fork::{ForkRecord, MAX_FORK_RECORD_BYTES, fork_key, fork_prefix};
pub use history::{AnchorEntry, MAX_ANCHOR_ENTRY_BYTES, anchor_entry_key, anchor_history_prefix};
pub use record::{
    AnchorRecord, CONSENSUS_KEY_BYTES, MAX_ANCHOR_RECORD_BYTES, anchor_key, deployment_id,
};
pub use revision::VerifiedRevision;

use super::VeraModule;
use crate::kv_store::ModuleKvStore as _;
use crate::types::BlockExecCtx;

/// Largest combined finality artifacts an anchor accepts, in bytes.
pub const MAX_ANCHOR_ARTIFACT_BYTES: usize = 256 << 10;

/// What an accepted submission did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchored {
    /// The deployment's latest anchor after the submission.
    pub record: AnchorRecord,
    /// Whether the submission recorded a new anchor; resubmitting the latest one does not.
    pub recorded: bool,
}

impl VeraModule {
    /// Record `revision` as the latest anchor of the deployment whose consensus
    /// key has canonical encoding `consensus_key`.
    ///
    /// The caller must have verified that `revision` is finalized under that
    /// key and that `revision.ancestor`, when set, is an ancestor of it. A
    /// deployment's first anchor needs no ancestor; every later one must name
    /// the latest anchor.
    pub fn record_anchor(
        &mut self,
        block_ctx: &BlockExecCtx,
        consensus_key: &[u8],
        revision: &VerifiedRevision,
    ) -> Result<Anchored, AnchorError> {
        if consensus_key.len() != CONSENSUS_KEY_BYTES {
            return Err(AnchorError::InvalidConsensusKey);
        }
        let deployment = deployment_id(consensus_key);
        let latest = self.latest_anchor(&deployment)?;
        if let Some(latest) = &latest {
            if latest.height == revision.height && latest.block_hash == revision.block_hash {
                return Ok(Anchored {
                    record: latest.clone(),
                    recorded: false,
                });
            }
            if revision.height <= latest.height {
                return Err(AnchorError::NotNewer {
                    latest: latest.height,
                    height: revision.height,
                });
            }
            if revision.term < latest.term {
                return Err(AnchorError::LowerTerm {
                    latest: latest.term,
                    term: revision.term,
                });
            }
            if revision.ancestor != Some((latest.height, latest.block_hash)) {
                return Err(AnchorError::NotDescendant {
                    latest: latest.height,
                    height: revision.height,
                });
            }
        }
        let record = AnchorRecord {
            deployment,
            consensus_key: consensus_key.to_vec().into(),
            sequence: latest.map_or(1, |latest| latest.sequence + 1),
            height: revision.height,
            block_hash: revision.block_hash,
            term: revision.term,
            timestamp: revision.timestamp,
            module_state_root: revision.module_state_root,
            anchored_at: block_ctx.timestamp.block_height,
        };
        self.store.put(&anchor_key(&deployment), record.encode());
        self.append_anchor_entry(&record);
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
