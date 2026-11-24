//! The terms a deployment's operators certified, as this deployment recorded them.
//!
//! A term certificate moves a deployment's active role to another device and
//! names the cut: the block the new term builds on. Blocks above the cut in a
//! lower term are void, so the anchors of such blocks are superseded and the
//! deployment's chain of anchors continues from the cut.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use super::{AnchorError, AnchorRecord, DeploymentRecord, deployment_key};
use crate::kv_store::ModuleKvStore as _;
use crate::types::BlockExecCtx;
use crate::vera::VeraModule;

const KEY_PREFIX: &[u8] = b"anchor-term/v1/";
/// Longest stored term record, in bytes.
pub const MAX_TERM_RECORD_BYTES: usize = 640;

/// Prefix of every term record of `deployment` in the identity partition.
/// Records follow it in term order.
#[must_use]
pub fn term_prefix(deployment: &B256) -> Vec<u8> {
    [KEY_PREFIX, hex::encode(deployment).as_bytes(), b"/"].concat()
}

/// Storage key of the record of `term` of `deployment`.
#[must_use]
pub fn term_key(deployment: &B256, term: u64) -> Vec<u8> {
    [
        term_prefix(deployment).as_slice(),
        format!("{term:016x}").as_bytes(),
    ]
    .concat()
}

/// A term change whose certificate the caller verified against the
/// deployment's registered genesis block and operator policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedTerm {
    /// The term that starts.
    pub term: u64,
    /// Transport key of the device that is active in the term.
    pub holder: B256,
    /// Height of the block the term builds on.
    pub cut_height: u64,
    /// Identifier of that block.
    pub cut_block: B256,
}

/// A certified term of a deployment as stored and as proven to readers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermRecord {
    /// The deployment's identifier.
    pub deployment: B256,
    /// The term.
    pub term: u64,
    /// Transport key of the device that is active in the term.
    pub holder: B256,
    /// Height of the block the term builds on.
    pub cut_height: u64,
    /// Identifier of that block.
    pub cut_block: B256,
    /// Sequence of the deployment's latest anchor when the term was recorded;
    /// 0 when it had none. Anchors up to it that the cut does not keep are superseded.
    pub sequence: u64,
    /// Height of the revision of this deployment that recorded the term.
    pub recorded_at: u64,
}

impl TermRecord {
    /// Decode the record stored at `key` and check it is the record that key names.
    pub fn decode(deployment: &B256, key: &[u8], bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > MAX_TERM_RECORD_BYTES {
            return Err(AnchorError::MalformedRecord);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| AnchorError::MalformedRecord)?;
        if record.deployment != *deployment
            || record.term == 0
            || term_key(deployment, record.term) != key
        {
            return Err(AnchorError::MalformedRecord);
        }
        Ok(record)
    }

    /// Canonical stored encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("term records serialize")
    }

    /// Whether this term voided the anchor numbered `sequence` of the block
    /// `block_hash` at `height`: it was recorded before the term, and it lies
    /// above the cut or is another block at the cut's height.
    #[must_use]
    pub fn supersedes(&self, sequence: u64, height: u64, block_hash: &B256) -> bool {
        sequence <= self.sequence
            && (height > self.cut_height
                || (height == self.cut_height && *block_hash != self.cut_block))
    }
}

/// Where a deployment's chain of anchors stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lineage {
    /// The latest anchor recorded, which the current term may have superseded.
    pub latest: Option<AnchorRecord>,
    /// The term certified last; `None` in term 0.
    pub term: Option<TermRecord>,
}

impl Lineage {
    /// The term a block above the tip must carry.
    #[must_use]
    pub fn certified_term(&self) -> u64 {
        self.term.as_ref().map_or(0, |term| term.term)
    }

    /// Height and identifier of the block the next anchor must descend from:
    /// the latest anchor recorded in the current term, or else that term's
    /// cut. `None` before the first anchor of a deployment in term 0.
    #[must_use]
    pub const fn tip(&self) -> Option<(u64, B256)> {
        match (&self.latest, &self.term) {
            (Some(latest), Some(term)) if latest.sequence > term.sequence => {
                Some((latest.height, latest.block_hash))
            }
            (_, Some(term)) => Some((term.cut_height, term.cut_block)),
            (Some(latest), None) => Some((latest.height, latest.block_hash)),
            (None, None) => None,
        }
    }

    /// Whether the current term voids a block of `term` at `height`: it lies
    /// above the cut in a lower term.
    #[must_use]
    pub fn voids(&self, height: u64, term: u64) -> bool {
        self.term
            .as_ref()
            .is_some_and(|certified| height > certified.cut_height && term < certified.term)
    }
}

impl VeraModule {
    /// The record of `term` of `deployment`, if it was recorded.
    pub fn term_record(
        &self,
        deployment: &B256,
        term: u64,
    ) -> Result<Option<TermRecord>, AnchorError> {
        let key = term_key(deployment, term);
        self.store
            .get(&key)
            .map(|bytes| TermRecord::decode(deployment, &key, &bytes))
            .transpose()
    }

    /// Where the chain of anchors of the registered deployment stands.
    pub fn lineage(&self, registered: &DeploymentRecord) -> Result<Lineage, AnchorError> {
        let term = match registered.term {
            0 => None,
            term => Some(
                self.term_record(&registered.deployment, term)?
                    .ok_or(AnchorError::MalformedRecord)?,
            ),
        };
        Ok(Lineage {
            latest: self.latest_anchor(&registered.deployment)?,
            term,
        })
    }

    /// Record a certified term of the registered `deployment`.
    ///
    /// The caller must have verified the term's certificate against the
    /// deployment's registered genesis block and operator policy. The term
    /// must be above the one recorded last. From then on the deployment's
    /// anchors continue from the cut, in the new term.
    pub fn record_term(
        &mut self,
        block_ctx: &BlockExecCtx,
        deployment: &B256,
        verified: &VerifiedTerm,
    ) -> Result<TermRecord, AnchorError> {
        let mut registered = self.registered_deployment(deployment)?;
        if verified.term <= registered.term {
            return Err(AnchorError::TermNotNewer {
                certified: registered.term,
                term: verified.term,
            });
        }
        let record = TermRecord {
            deployment: registered.deployment,
            term: verified.term,
            holder: verified.holder,
            cut_height: verified.cut_height,
            cut_block: verified.cut_block,
            sequence: self
                .latest_anchor(deployment)?
                .map_or(0, |latest| latest.sequence),
            recorded_at: block_ctx.timestamp.block_height,
        };
        registered.term = record.term;
        self.store
            .put(&term_key(deployment, record.term), record.encode());
        self.store
            .put(&deployment_key(deployment), registered.encode());
        Ok(record)
    }
}
