//! Proofs that a retained block is an ancestor of a later one.
//!
//! A block carries the peaks of the range over its ancestors, so the proof is
//! rebuilt from the ancestor's own block and the identifiers of the blocks
//! after it. History keeps each block's identifier under its height, 32 bytes
//! beside the record, so a proof reads two records whatever the span.

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
    /// Reads the ancestor's and the block's records and the identifier of
    /// every block between them, from one snapshot of the store, and checks
    /// the proof against the block before returning it. An ancestor below the
    /// floor fails with [`HistoryPruned`], and a pair the store cannot relate
    /// with [`AncestryUnavailable`].
    pub(crate) fn ancestry_proof(&self, ancestor: u64, height: u64) -> Result<AncestryProof> {
        let (head, snapshot) = {
            let head = self.head.lock();
            (head.0, self.db.snapshot())
        };
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
        let block_at = |height: u64| -> Result<Block> {
            let bytes = snapshot
                .get(key(RECORD, height))?
                .with_context(|| format!("missing finalized record {height}"))?;
            let record: Record = borsh::from_slice(&bytes)?;
            Ok(Block::decode_cfg(
                commonware_codec::Copying(record.block.as_slice()),
                &crate::node::block_cfg(),
            )?)
        };
        let id_at = |height: u64| -> Result<BlockId> {
            let bytes = if height == 0 {
                snapshot.get(GENESIS)?
            } else {
                snapshot.get(key(BLOCK_ID, height))?
            }
            .with_context(|| format!("missing block identifier {height}"))?;
            let id: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .context("block identifier is not 32 bytes")?;
            Ok(BlockId(B256::from(id)))
        };
        let base = if ancestor == 0 {
            Ancestry::genesis()
        } else {
            block_at(ancestor)?.ancestry
        };
        let ids = (ancestor..height).map(id_at).collect::<Result<Vec<_>>>()?;
        let proof = base.prove(ancestor, &ids, ancestor)?;
        let block = block_at(height)?;
        ensure!(
            Some(&block.parent) == ids.last() && block.has_ancestor(ancestor, &ids[0], &proof),
            "stored block identifiers do not match revision {height}"
        );
        Ok(proof)
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

    #[test]
    fn a_proof_reads_the_identifiers_between_and_not_their_records() {
        let dir = tempfile::tempdir().unwrap();
        let blocks = chain(12);
        let history = FinalizedHistory::open(dir.path(), &blocks[0]).unwrap();
        for block in &blocks[1..] {
            history.append_finalized(block, &[], 100, None).unwrap();
        }
        for height in 3..10 {
            history.db.delete(key(RECORD, height)).unwrap();
        }
        let proof = history.ancestry_proof(2, 10).unwrap();
        assert!(blocks[10].has_ancestor(2, &blocks[2].id(), &proof));

        // An identifier that is not the block's is caught before the proof leaves.
        history
            .db
            .put(key(BLOCK_ID, 6), blocks[7].id().0.0)
            .unwrap();
        let error = history.ancestry_proof(2, 10).unwrap_err();
        assert!(error.to_string().contains("do not match"), "{error}");
        history.db.delete(key(BLOCK_ID, 6)).unwrap();
        let error = history.ancestry_proof(2, 10).unwrap_err();
        assert!(
            error.to_string().contains("missing block identifier"),
            "{error}"
        );
    }

    #[test]
    fn a_rewind_drops_the_identifiers_above_its_cut() {
        let dir = tempfile::tempdir().unwrap();
        let blocks = chain(8);
        let history = FinalizedHistory::open(dir.path(), &blocks[0]).unwrap();
        for block in &blocks[1..] {
            history.append_finalized(block, &[], 100, None).unwrap();
        }
        history.rewind_to(5).unwrap();
        assert!(history.db.get(key(BLOCK_ID, 5)).unwrap().is_some());
        for height in 6..=8 {
            assert!(history.db.get(key(BLOCK_ID, height)).unwrap().is_none());
        }
        let proof = history.ancestry_proof(1, 5).unwrap();
        assert!(blocks[5].has_ancestor(1, &blocks[1].id(), &proof));
    }

    #[tokio::test]
    async fn a_rebuilding_recovery_restores_identifiers_that_are_missing_or_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let blocks = chain(12);
        let history = FinalizedHistory::open(dir.path(), &blocks[0]).unwrap();
        for block in &blocks[1..] {
            history.append_finalized(block, &[], 100, None).unwrap();
        }
        history.db.delete(key(BLOCK_ID, 4)).unwrap();
        history
            .db
            .put(key(BLOCK_ID, 7), blocks[8].id().0.0)
            .unwrap();
        assert!(history.ancestry_proof(2, 10).is_err());
        // Mappings whose head does not match are rebuilt by the next recovery.
        history.db.delete(QUERY_HEAD).unwrap();
        drop(history);

        let history = FinalizedHistory::open(dir.path(), &blocks[0]).unwrap();
        let lookup: crate::FinalizationLookup = std::sync::Arc::new(|_| Box::pin(async { None }));
        history
            .recover(
                &blocks[0],
                &blocks[12],
                &BlockIndex::new(),
                &LightBlockIndex::new(std::num::NonZeroU64::new(20).unwrap()),
                &lookup,
            )
            .await
            .unwrap();
        for height in [4, 7] {
            assert_eq!(
                history.db.get(key(BLOCK_ID, height)).unwrap().unwrap(),
                blocks[height as usize].id().0.0.to_vec()
            );
        }
        let proof = history.ancestry_proof(2, 10).unwrap();
        assert!(blocks[10].has_ancestor(2, &blocks[2].id(), &proof));
    }
}
