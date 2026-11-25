//! Query-mapping maintenance when recovery discards a short history suffix.

use std::collections::HashSet;

use super::*;

/// Longest discarded suffix unindexed in place; a longer one rebuilds every mapping.
pub(super) const MAX_SUFFIX: u64 = 1_024;

/// Deletions that unindex a discarded suffix, applied with the head rewind.
#[derive(Default)]
pub(super) struct SuffixRewind {
    pub batch: WriteBatch,
    /// Submission hashes the suffix indexed. A retained revision carrying one
    /// of them regains the mapping the suffix overwrote.
    pub displaced: HashSet<[u8; 32]>,
}

impl FinalizedHistory {
    /// Stage the removal of mappings written by records above `anchor`.
    ///
    /// Returns `None` when the mappings cannot be trusted up to the durable
    /// head, or the suffix is too long or unreadable; recovery then rebuilds
    /// all of them.
    pub(super) fn suffix_rewind(
        &self,
        anchor: u64,
        indexed: Option<&[u8]>,
    ) -> Result<Option<SuffixRewind>> {
        let head = *self.head.lock();
        if indexed != Some(borsh::to_vec(&(head.0, head.1.0.0))?.as_slice())
            || head.0 <= anchor
            || head.0 - anchor > MAX_SUFFIX
            || self.db.get(transfer::IMPORT)?.is_some()
        {
            return Ok(None);
        }
        let mut rewind = SuffixRewind::default();
        for height in anchor + 1..=head.0 {
            let Some(bytes) = self.db.get(key(RECORD, height))? else {
                return Ok(None);
            };
            let Ok(record) = borsh::from_slice::<Record>(&bytes) else {
                return Ok(None);
            };
            let Ok(block) = Block::decode_cfg(
                commonware_codec::Copying(record.block.as_slice()),
                &crate::node::block_cfg(),
            ) else {
                return Ok(None);
            };
            query::unindex_execution(&mut rewind.batch, &block, &record.receipts);
            rewind
                .displaced
                .extend(record.receipts.iter().map(|receipt| receipt.hash));
        }
        Ok(Some(rewind))
    }
}

/// Point a displaced submission hash back at the retained revision carrying it.
pub(super) fn restore_displaced(
    batch: &mut WriteBatch,
    height: u64,
    receipts: &[StoredReceipt],
    displaced: &HashSet<[u8; 32]>,
) {
    if displaced.is_empty() {
        return;
    }
    for receipt in receipts {
        if displaced.contains(&receipt.hash) {
            query::index_submission(batch, &receipt.hash, height);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{query::hash_key, tests::block};
    use std::{num::NonZeroU64, sync::Arc};

    const SHARED: B256 = B256::repeat_byte(7);
    const STRAY: [u8; 32] = [0xee; 32];

    fn revision(height: u64, parent: BlockId, submission: B256) -> (Block, ExecutionReceipt) {
        let mut next = block(height, parent);
        next.txs
            .push(vera_domain::Tx::new(vec![height as u8].into()));
        let receipt = ExecutionReceipt::new(submission, true, 3, 3, vec![]);
        next.native_targets = [vera_domain::DbTarget::default(); 4];
        next.receipt_commitment =
            vera_executor::receipt_commitment(100, std::slice::from_ref(&receipt));
        (next, receipt)
    }

    struct Chain {
        history: FinalizedHistory,
        genesis: Block,
        blocks: Vec<Block>,
        _directory: tempfile::TempDir,
    }

    /// Three revisions; the third repeats the first one's submission hash. A
    /// key no record owns shows whether recovery cleared the whole index.
    fn chain() -> Chain {
        let directory = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
        let mut blocks = Vec::new();
        let mut parent = genesis.id();
        for (height, submission) in [(1, SHARED), (2, B256::repeat_byte(8)), (3, SHARED)] {
            let (next, receipt) = revision(height, parent, submission);
            history
                .append(&next, std::slice::from_ref(&receipt), 100)
                .unwrap();
            parent = next.id();
            blocks.push(next);
        }
        history
            .db
            .put(hash_key(BLOCK_HASH, &STRAY), 1_u64.to_be_bytes())
            .unwrap();
        Chain {
            history,
            genesis,
            blocks,
            _directory: directory,
        }
    }

    impl Chain {
        async fn recover(&self, anchor: usize) {
            let lookup: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
            self.history
                .recover(
                    &self.genesis,
                    &self.blocks[anchor - 1],
                    &BlockIndex::new(),
                    &LightBlockIndex::new(NonZeroU64::new(20).unwrap()),
                    &lookup,
                )
                .await
                .unwrap();
        }

        fn submission(&self, hash: B256) -> Option<u64> {
            self.history
                .execution_by_submission(hash)
                .unwrap()
                .map(|execution| execution.block.height)
        }

        fn revision(&self, height: usize) -> Option<u64> {
            self.history
                .execution_by_hash(self.blocks[height - 1].id().0)
                .unwrap()
                .map(|execution| execution.block.height)
        }

        fn kept_whole_index(&self) -> bool {
            let stray = self.history.db.get(hash_key(BLOCK_HASH, &STRAY));
            stray.unwrap().is_some()
        }
    }

    #[tokio::test]
    async fn discarded_suffix_is_unindexed_without_rebuilding_earlier_mappings() {
        let chain = chain();
        assert_eq!(chain.submission(SHARED), Some(3));
        chain.recover(2).await;
        assert!(chain.kept_whole_index());
        assert_eq!(chain.revision(3), None);
        assert_eq!(chain.revision(2), Some(2));
        assert_eq!(chain.revision(1), Some(1));
        assert_eq!(chain.submission(B256::repeat_byte(8)), Some(2));
        // The mapping the suffix overwrote points at its retained revision again.
        assert_eq!(chain.submission(SHARED), Some(1));
        let (third, receipt) = revision(3, chain.blocks[1].id(), SHARED);
        chain
            .history
            .append(&third, std::slice::from_ref(&receipt), 100)
            .unwrap();
        assert_eq!(chain.submission(SHARED), Some(3));
    }

    #[tokio::test]
    async fn untrusted_index_or_unreadable_suffix_rebuilds_every_mapping() {
        for damage in ["query head", "suffix record"] {
            let chain = chain();
            match damage {
                "query head" => chain.history.db.delete(QUERY_HEAD).unwrap(),
                _ => chain.history.db.put(key(RECORD, 3), [0xff]).unwrap(),
            }
            chain.recover(2).await;
            assert!(!chain.kept_whole_index(), "{damage}");
            assert_eq!(chain.revision(3), None, "{damage}");
            assert_eq!(chain.revision(2), Some(2), "{damage}");
            assert_eq!(chain.submission(SHARED), Some(1), "{damage}");
        }
    }

    #[tokio::test]
    async fn recovery_at_the_indexed_head_leaves_mappings_alone() {
        let chain = chain();
        chain.recover(3).await;
        assert!(chain.kept_whole_index());
        assert_eq!(chain.submission(SHARED), Some(3));
    }
}
