//! Evidence that a deployment finalized two histories.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use super::{AnchorError, VerifiedRevision};
use crate::kv_store::ModuleKvStore as _;
use crate::types::BlockExecCtx;
use crate::vera::VeraModule;

const KEY_PREFIX: &[u8] = b"anchor-fork/v1/";
/// Longest stored fork record, in bytes.
pub const MAX_FORK_RECORD_BYTES: usize = 1024;

/// Prefix of every fork record of `deployment` in the identity partition.
#[must_use]
pub fn fork_prefix(deployment: &B256) -> Vec<u8> {
    [KEY_PREFIX, hex::encode(deployment).as_bytes(), b"/"].concat()
}

/// Storage key of the fork record of `deployment` for the conflicting block `block_hash`.
#[must_use]
pub fn fork_key(deployment: &B256, block_hash: &B256) -> Vec<u8> {
    [
        fork_prefix(deployment).as_slice(),
        hex::encode(block_hash).as_bytes(),
    ]
    .concat()
}

/// The conflicting block whose fork record `key` names, when it is a fork key
/// of `deployment`.
#[must_use]
pub fn fork_block_of_key(deployment: &B256, key: &[u8]) -> Option<B256> {
    let block = key.strip_prefix(fork_prefix(deployment).as_slice())?;
    let block = B256::from(<[u8; 32]>::try_from(hex::decode(block).ok()?).ok()?);
    (fork_key(deployment, &block) == key).then_some(block)
}

/// A finalized block of a deployment that does not descend from the tip of
/// its chain of anchors when the block was reported: its latest anchor, or
/// the cut of a term certified since.
///
/// The block carries the deployment's certificate, and so does the anchored
/// one, so the deployment's key finalized two histories that part at or below
/// the anchored height.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkRecord {
    /// The deployment's identifier.
    pub deployment: B256,
    /// Sequence of the deployment's latest anchor when the fork was reported.
    pub sequence: u64,
    /// Height of the tip the block conflicts with.
    pub anchored_height: u64,
    /// Identifier of the block at the tip.
    pub anchored_block: B256,
    /// Height of the conflicting block.
    pub height: u64,
    /// Identifier of the conflicting block.
    pub block_hash: B256,
    /// Term of the conflicting block.
    pub term: u64,
    /// The conflicting block's ancestor at the anchored height; the block
    /// itself when it is at that height.
    pub ancestor: B256,
    /// Height of the revision of this deployment that recorded the fork.
    pub reported_at: u64,
}

impl ForkRecord {
    /// Decode a stored record and check it belongs to `deployment`.
    pub fn decode(deployment: &B256, bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > MAX_FORK_RECORD_BYTES {
            return Err(AnchorError::MalformedRecord);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| AnchorError::MalformedRecord)?;
        if record.deployment != *deployment
            || record.ancestor == record.anchored_block
            || record.height < record.anchored_height
        {
            return Err(AnchorError::MalformedRecord);
        }
        Ok(record)
    }

    /// Canonical stored encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fork records serialize")
    }
}

impl VeraModule {
    /// Record `revision` as a fork of the registered `deployment`.
    ///
    /// The caller must have verified that `revision` is finalized under the
    /// deployment's registered key and that `revision.ancestor`, when set, is
    /// an ancestor of it. The block conflicts with the tip of the
    /// deployment's [`super::Lineage`] when it is another block at the tip's
    /// height, or lies above it with another ancestor at that height. A block
    /// the certified term voids is no fork.
    pub fn record_fork(
        &mut self,
        block_ctx: &BlockExecCtx,
        deployment: &B256,
        revision: &VerifiedRevision,
    ) -> Result<ForkRecord, AnchorError> {
        let registered = self.registered_deployment(deployment)?;
        let deployment = registered.deployment;
        let lineage = self.lineage(&registered)?;
        let (tip_height, tip_block) = lineage.tip().ok_or(AnchorError::NoAnchor)?;
        let not_a_fork = AnchorError::NotAFork {
            latest: tip_height,
            height: revision.height,
        };
        // A block the certified term voids is explained by the term.
        if lineage.voids(revision.height, revision.term) {
            return Err(not_a_fork);
        }
        let ancestor = if revision.height == tip_height {
            Some(revision.block_hash)
        } else {
            revision
                .ancestor
                .filter(|(height, _)| revision.height > tip_height && *height == tip_height)
                .map(|(_, ancestor)| ancestor)
        };
        let ancestor = ancestor
            .filter(|ancestor| *ancestor != tip_block)
            .ok_or(not_a_fork)?;
        let key = fork_key(&deployment, &revision.block_hash);
        if self.store.has(&key) {
            return Err(AnchorError::ForkRecorded);
        }
        let record = ForkRecord {
            deployment,
            sequence: lineage.latest.map_or(0, |latest| latest.sequence),
            anchored_height: tip_height,
            anchored_block: tip_block,
            height: revision.height,
            block_hash: revision.block_hash,
            term: revision.term,
            ancestor,
            reported_at: block_ctx.timestamp.block_height,
        };
        self.store.put(&key, record.encode());
        Ok(record)
    }

    /// Every recorded fork of `deployment`, ordered by the conflicting block's identifier.
    pub fn forks(&self, deployment: &B256) -> Result<Vec<ForkRecord>, AnchorError> {
        self.store
            .prefix_scan(&fork_prefix(deployment))
            .iter()
            .map(|(_, bytes)| ForkRecord::decode(deployment, bytes))
            .collect()
    }
}
