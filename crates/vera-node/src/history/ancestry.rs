//! Proofs that a retained block is an ancestor of a later one.
//!
//! A block carries the peaks of the range over its ancestors, so the proof is
//! rebuilt from the ancestor's own block and the identifiers of the blocks
//! after it. Nothing beyond the retained records is stored.

use vera_domain::{Ancestry, AncestryProof};

use super::*;

/// Most blocks between an ancestor and the block a proof is for.
pub(crate) const MAX_ANCESTRY_SPAN: u64 = 65_536;

/// A proof was asked for a pair of revisions that the store cannot relate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AncestryUnavailable {
    /// The ancestor is not below the block, or the block is not finalized here.
    #[error("revision {ancestor} is not below revision {height} of a history at {head}")]
    Order {
        /// Height of the ancestor asked for.
        ancestor: u64,
        /// Height of the block the proof is for.
        height: u64,
        /// Newest revision in the store.
        head: u64,
    },
    /// More than [`MAX_ANCESTRY_SPAN`] blocks lie between the two.
    #[error("revision {ancestor} is more than {MAX_ANCESTRY_SPAN} blocks below revision {height}")]
    Span {
        /// Height of the ancestor asked for.
        ancestor: u64,
        /// Height of the block the proof is for.
        height: u64,
    },
}

/// The RPC error of a failed proof: a pruned ancestor keeps its own code, and
/// a pair the store cannot relate is the caller's.
pub(crate) fn ancestry_rpc_error(error: &anyhow::Error) -> vera_jsonrpc::RpcError {
    if let Some(unavailable) = error.downcast_ref::<AncestryUnavailable>() {
        return vera_jsonrpc::RpcError::InvalidParams(unavailable.to_string());
    }
    rpc_error(error, vera_jsonrpc::RpcError::Internal)
}

impl FinalizedHistory {
    /// Prove that the block at `ancestor` is an ancestor of the block at `height`.
    ///
    /// Reads every record between the two. An ancestor below the floor fails
    /// with [`HistoryPruned`], and a pair the store cannot relate with
    /// [`AncestryUnavailable`].
    pub(crate) fn ancestry_proof(&self, ancestor: u64, height: u64) -> Result<AncestryProof> {
        let head = self.head.lock().0;
        if ancestor >= height || height > head {
            return Err(AncestryUnavailable::Order {
                ancestor,
                height,
                head,
            }
            .into());
        }
        if height - ancestor > MAX_ANCESTRY_SPAN {
            return Err(AncestryUnavailable::Span { ancestor, height }.into());
        }
        check_cut(ancestor, self.floor_height()?)?;
        let base = if ancestor == 0 {
            Ancestry::genesis()
        } else {
            self.block(ancestor)?.ancestry
        };
        let ids = (ancestor + 1..=height)
            .map(|height| Ok(self.block(height)?.parent))
            .collect::<Result<Vec<_>>>()?;
        Ok(base.prove(ancestor, &ids, ancestor)?)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::chain;
    use super::*;

    #[test]
    fn an_ancestor_is_proven_from_the_records_since_it() {
        let dir = tempfile::tempdir().unwrap();
        let blocks = chain(12);
        let history = FinalizedHistory::open(dir.path(), &blocks[0]).unwrap();
        for block in &blocks[1..] {
            history.append_finalized(block, &[], 100, None).unwrap();
        }
        for (ancestor, height) in [(0, 1), (0, 12), (5, 6), (5, 12), (11, 12), (3, 9)] {
            let proof = history.ancestry_proof(ancestor, height).unwrap();
            let block = &blocks[height as usize];
            let id = blocks[ancestor as usize].id();
            assert!(
                block.has_ancestor(ancestor, &id, &proof),
                "{ancestor} in {height}"
            );
            assert!(!block.has_ancestor(ancestor, &block.id(), &proof));
        }
        for (ancestor, height) in [(5, 5), (6, 5), (5, 13)] {
            let error = history.ancestry_proof(ancestor, height).unwrap_err();
            assert!(error.is::<AncestryUnavailable>(), "{ancestor} in {height}");
        }
    }
}
