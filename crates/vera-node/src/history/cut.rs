//! Dropping the finalized records a switch of the active device voided.

use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};

use super::*;

/// A finalized submission that a switch of the active device voided.
///
/// The device that was replaced finalized it above the cut of the term that
/// replaced it, so no other device holds it. It is not part of the
/// deployment's history, and its effect on state is gone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscardedSubmission {
    /// Identifier of the submission, as its receipt was looked up.
    pub submission: B256,
    /// Height of the voided block that carried it.
    pub height: u64,
    /// Whether it had succeeded.
    pub success: bool,
    /// The signed request as it was submitted.
    pub request: Bytes,
}

/// Where a store stands against the block a term builds on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// Every record is the cut, an ancestor of it, or a block of the term.
    Within,
    /// The records above the cut are in a lower term than the one that
    /// builds on it: the term voided them.
    Above,
    /// The record at the cut's height is another block.
    Diverged,
}

impl FinalizedHistory {
    /// Open the store of the deployment `genesis` while no node runs on it.
    pub(crate) fn open_stored(
        path: &Path,
        genesis: &B256,
        memory: Option<HistoryMemory>,
    ) -> Result<Self> {
        ensure!(path.is_dir(), "finalized history is missing");
        Self::open_identified(path, genesis, memory)
    }

    /// Compare the store with the block `cut` at `height`, which `term` builds on.
    ///
    /// A term never decreases along a chain, so the first record above the
    /// cut tells whether the rest belong to the term or were voided by it.
    pub(crate) fn standing(&self, height: u64, cut: &B256, term: u64) -> Result<Standing> {
        let head = *self.head.lock();
        if head.0 < height {
            return Ok(Standing::Within);
        }
        let held = if head.0 == height {
            head.1.0
        } else if height == 0 {
            B256::from_slice(&self.db.get(GENESIS)?.context("missing history genesis")?)
        } else {
            self.block(height)?.id().0
        };
        if held != *cut {
            return Ok(Standing::Diverged);
        }
        if head.0 > height && self.block(height + 1)?.term < term {
            return Ok(Standing::Above);
        }
        Ok(Standing::Within)
    }

    fn record(&self, height: u64) -> Result<Record> {
        let bytes = self
            .db
            .get(key(RECORD, height))?
            .with_context(|| format!("missing finalized record {height}"))?;
        Ok(borsh::from_slice(&bytes)?)
    }

    fn block(&self, height: u64) -> Result<Block> {
        Ok(Block::decode_cfg(
            commonware_codec::Copying(self.record(height)?.block.as_slice()),
            &crate::node::block_cfg(),
        )?)
    }

    /// Every submission finalized above `height`, in execution order.
    pub(crate) fn submissions_above(&self, height: u64) -> Result<Vec<DiscardedSubmission>> {
        let head = self.head.lock().0;
        let mut submissions = Vec::new();
        for height in height.saturating_add(1)..=head {
            let record = self.record(height)?;
            let block = Block::decode_cfg(
                commonware_codec::Copying(record.block.as_slice()),
                &crate::node::block_cfg(),
            )?;
            ensure!(
                block.txs.len() == record.receipts.len(),
                "incomplete execution record"
            );
            for (tx, receipt) in block.txs.iter().zip(&record.receipts) {
                submissions.push(DiscardedSubmission {
                    submission: B256::from(receipt.hash),
                    height,
                    success: receipt.success,
                    request: tx.bytes.clone(),
                });
            }
        }
        Ok(submissions)
    }

    /// Drop every record above `height`. The query mappings are dropped with
    /// them and rebuilt by the next recovery.
    pub(crate) fn rewind_to(&self, height: u64) -> Result<()> {
        let mut head = self.head.lock();
        if head.0 <= height {
            return Ok(());
        }
        let id = if height == 0 {
            B256::from_slice(&self.db.get(GENESIS)?.context("missing history genesis")?)
        } else {
            self.block(height)?.id().0
        };
        let mut batch = WriteBatch::default();
        let next = height + 1;
        for prefix in [RECORD, CERTIFICATE, IMPORTED_FINALITY, PROOF_BLOCK] {
            batch.delete_range(key(prefix, next).as_slice(), &[prefix + 1]);
        }
        batch.delete_range([BLOCK_HASH], [SUBMISSION_HASH + 1]);
        batch.delete(QUERY_HEAD);
        // An import interrupted above the cut staged records of the voided
        // blocks; the next start selects a block of the term to import from.
        batch.delete(transfer::IMPORT);
        batch.put(HEAD, borsh::to_vec(&(height, id.0))?);
        self.cut_validated(height, &id, &mut batch)?;
        write(&self.db, batch)?;
        *head = (height, BlockId(id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::tests::block;
    use std::{num::NonZeroU64, sync::Arc};

    fn revision(height: u64, parent: BlockId, submission: B256) -> (Block, ExecutionReceipt) {
        let mut next = block(height, parent);
        next.txs
            .push(vera_domain::Tx::new(vec![height as u8].into()));
        let receipt = ExecutionReceipt::new(submission, height != 2, 3, 3, vec![], None);
        next.native_targets = Some([vera_domain::DbTarget::default(); 4]);
        next.receipt_commitment = Some(vera_executor::receipt_commitment(
            100,
            std::slice::from_ref(&receipt),
        ));
        (next, receipt)
    }

    #[tokio::test]
    async fn records_above_the_cut_are_reported_and_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let mut blocks = Vec::new();
        {
            let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
            let mut parent = genesis.id();
            for height in 1..=3 {
                let (next, receipt) = revision(height, parent, B256::repeat_byte(height as u8));
                history
                    .append(&next, std::slice::from_ref(&receipt), 100)
                    .unwrap();
                parent = next.id();
                blocks.push(next);
            }
        }
        assert!(
            FinalizedHistory::open_stored(directory.path(), &B256::repeat_byte(9), None).is_err(),
            "another deployment's store"
        );
        let history =
            FinalizedHistory::open_stored(directory.path(), &genesis.id().0, None).unwrap();
        let cut = blocks[0].id().0;
        assert_eq!(history.standing(1, &cut, 1).unwrap(), Standing::Above);
        assert_eq!(
            history.standing(0, &genesis.id().0, 1).unwrap(),
            Standing::Above
        );
        assert_eq!(
            history.standing(1, &blocks[1].id().0, 1).unwrap(),
            Standing::Diverged
        );
        assert_eq!(
            history.standing(3, &blocks[2].id().0, 1).unwrap(),
            Standing::Within
        );
        assert_eq!(history.standing(3, &cut, 1).unwrap(), Standing::Diverged);
        assert_eq!(history.standing(4, &cut, 1).unwrap(), Standing::Within);

        // Records above the cut that are already in the term belong to it.
        assert_eq!(history.standing(1, &cut, 0).unwrap(), Standing::Within);

        // An import that was interrupted does not keep the store from being cut back.
        history.db.put(transfer::IMPORT, [0xff]).unwrap();
        let discarded = history.submissions_above(1).unwrap();
        assert_eq!(
            discarded,
            [2u8, 3].map(|height| DiscardedSubmission {
                submission: B256::repeat_byte(height),
                height: height.into(),
                success: height != 2,
                request: vec![height].into(),
            })
        );
        history.rewind_to(1).unwrap();
        assert_eq!(history.head_height(), 1);
        assert!(history.import_anchor().unwrap().is_none());
        assert_eq!(history.standing(1, &cut, 1).unwrap(), Standing::Within);
        assert!(history.submissions_above(1).unwrap().is_empty());
        history.rewind_to(1).unwrap();
        drop(history);

        // The node's recovery rebuilds the mappings of what is left, and the next block follows the cut.
        let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
        let lookup: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
        history
            .recover(
                &genesis,
                &blocks[0],
                &BlockIndex::new(),
                &LightBlockIndex::new(NonZeroU64::new(20).unwrap()),
                &lookup,
            )
            .await
            .unwrap();
        let kept = history
            .execution_by_submission(B256::repeat_byte(1))
            .unwrap();
        assert_eq!(kept.map(|execution| execution.block.height), Some(1));
        assert!(
            history
                .execution_by_submission(B256::repeat_byte(3))
                .unwrap()
                .is_none()
        );
        assert!(
            history
                .execution_by_hash(blocks[2].id().0)
                .unwrap()
                .is_none()
        );
        let (other, receipt) = revision(2, blocks[0].id(), B256::repeat_byte(7));
        history
            .append(&other, std::slice::from_ref(&receipt), 100)
            .unwrap();
        assert_eq!(history.head_height(), 2);
    }
}
