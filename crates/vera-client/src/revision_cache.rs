//! Revisions whose finality this client has verified, so that each
//! finalization certificate is checked once.

use std::{collections::BTreeMap, sync::Mutex};

use alloy_primitives::B256;
use vera_domain::{
    Block, ConsensusPublicKey, FinalityTrust, FinalizedArtifacts, LightBlock, LightBlockError,
    verify_finalized_block_unless,
};

/// Revisions a client remembers unless configured otherwise.
pub const DEFAULT_VERIFIED_REVISIONS: usize = 256;

#[derive(Debug, Default)]
struct Verified {
    /// Key every remembered revision was verified under.
    trusted: Option<ConsensusPublicKey>,
    /// Highest term among the blocks verified under that key.
    term: u64,
    /// At each remembered height, the hash of the verified block and the
    /// [`FinalizedArtifacts::finality_digest`] of the evidence it verified with.
    blocks: BTreeMap<u64, Remembered>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Remembered {
    block: B256,
    evidence: B256,
}

/// A bounded record of verified revisions, keyed by height and block hash.
///
/// A response answers from the record only when it carries the very evidence
/// that was verified: the same block, descendants, finalization and epoch
/// material. Anything else is verified in full, so every response a reader
/// returns verifies under the key on its own.
///
/// A revision is remembered only in the newest term the client has verified
/// under one consensus key. A block of a later term, a second block at a
/// remembered height and a different key each empty the record, so what a
/// switch of the active device may have replaced is verified again.
#[derive(Debug)]
pub(crate) struct RevisionCache {
    capacity: usize,
    verified: Mutex<Verified>,
}

impl RevisionCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            verified: Mutex::default(),
        }
    }

    /// Whether exactly this block, with exactly this evidence, was verified
    /// under `trusted`.
    fn holds(&self, trusted: &ConsensusPublicKey, block: &Block, remembered: Remembered) -> bool {
        let verified = self.verified.lock().expect("revision cache lock poisoned");
        verified.trusted.as_ref() == Some(trusted)
            && verified.term == block.term
            && verified.blocks.get(&block.height) == Some(&remembered)
    }

    /// Remember a block whose certificate was just verified under `trusted`.
    fn remember(&self, trusted: &ConsensusPublicKey, block: &Block, remembered: Remembered) {
        if self.capacity == 0 {
            return;
        }
        let mut verified = self.verified.lock().expect("revision cache lock poisoned");
        if verified.trusted.as_ref() != Some(trusted) {
            *verified = Verified {
                trusted: Some(*trusted),
                ..Verified::default()
            };
        }
        if block.term < verified.term {
            return;
        }
        let replaced = verified
            .blocks
            .get(&block.height)
            .is_some_and(|known| known.block != remembered.block);
        if block.term > verified.term || replaced {
            verified.blocks.clear();
            verified.term = block.term;
        }
        verified.blocks.insert(block.height, remembered);
        while verified.blocks.len() > self.capacity {
            verified.blocks.pop_first();
        }
    }

    /// Finality checks under `trusted` that consult and extend this record.
    pub(crate) const fn under<'a>(&'a self, trusted: &'a ConsensusPublicKey) -> Established<'a> {
        Established {
            cache: self,
            trusted,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.verified.lock().unwrap().blocks.len()
    }
}

/// A consensus key paired with the revisions already verified under it.
#[derive(Debug)]
pub(crate) struct Established<'a> {
    cache: &'a RevisionCache,
    trusted: &'a ConsensusPublicKey,
}

impl FinalityTrust for Established<'_> {
    fn finalized_block(&self, light: &LightBlock) -> Result<Block, LightBlockError> {
        let mut seen = None;
        let (block, _) = verify_finalized_block_unless(
            light,
            self.trusted,
            |block, hash, artifacts: &FinalizedArtifacts| {
                let remembered = Remembered {
                    block: hash,
                    evidence: artifacts.finality_digest(),
                };
                let known = self.cache.holds(self.trusted, block, remembered);
                seen = Some((remembered, known));
                known
            },
        )?;
        if let Some((remembered, false)) = seen {
            self.cache.remember(self.trusted, &block, remembered);
        }
        Ok(block)
    }
}

#[cfg(test)]
#[path = "revision_cache_tests.rs"]
mod tests;
