//! How far the stored chain is known to be valid, so a start need not reread it.
//!
//! The `validated` key holds a height and block hash. It claims that every
//! record from genesis through that block decodes, matches its receipt
//! commitment and names its predecessor as parent. A start relies on it only
//! while it names the durable head.
//!
//! Only a write that establishes the claim stores it, in the same batch as
//! the records it covers: the first open (genesis), an append whose parent is
//! the validated head, a recovery that has checked the chain through its
//! anchor, and a cut back to a block of the validated chain. An import leaves
//! it where it was, below the imported records, so the recovery that
//! publishes them checks them all.

use super::*;
use vera_indexer::MAX_CACHED_EPOCHS;

pub(super) const VALIDATED: &[u8] = b"validated";

impl FinalizedHistory {
    /// Stage the validated head's move from `previous` to `next`, which a
    /// checked append extends it by. A store whose validated head is
    /// elsewhere keeps it there.
    pub(super) fn extend_validated(
        &self,
        previous: &(u64, BlockId),
        next: &[u8],
        batch: &mut WriteBatch,
    ) -> Result<()> {
        if self.db.get(VALIDATED)?.as_deref()
            == Some(borsh::to_vec(&(previous.0, previous.1.0.0))?.as_slice())
        {
            batch.put(VALIDATED, next);
        }
        Ok(())
    }

    /// Stage lowering the validated head to `height`, a block of the chain it
    /// covers, when records above `height` are removed.
    pub(super) fn cut_validated(
        &self,
        height: u64,
        id: &B256,
        batch: &mut WriteBatch,
    ) -> Result<()> {
        if self
            .validated()?
            .is_some_and(|(validated, _)| validated > height)
        {
            batch.put(VALIDATED, borsh::to_vec(&(height, id.0))?);
        }
        Ok(())
    }

    /// The stored validated head, `None` when absent or malformed.
    fn validated(&self) -> Result<Option<(u64, [u8; 32])>> {
        Ok(self
            .db
            .get(VALIDATED)?
            .and_then(|bytes| borsh::from_slice(&bytes).ok()))
    }

    /// Whether the chain through `height` was validated: the validated head
    /// is the durable head, at or above `height`, and the record stored at
    /// its height is the block it names.
    pub(super) fn validated_through(&self, genesis: &Block, height: u64) -> Result<bool> {
        let head = *self.head.lock();
        if self.validated()? != Some((head.0, head.1.0.0)) || head.0 < height {
            return Ok(false);
        }
        if head.0 == 0 {
            return Ok(head.1 == genesis.id());
        }
        let Some(bytes) = self.db.get(key(RECORD, head.0))? else {
            return Ok(false);
        };
        let Ok(record) = borsh::from_slice::<Record>(&bytes) else {
            return Ok(false);
        };
        Ok(alloy_primitives::keccak256(&record.block) == head.1.0)
    }

    /// Restore the epoch material that a walk of the records below `end`
    /// would have left in the cache: the newest epochs' artifacts, read from
    /// the last block of each preceding epoch.
    ///
    /// A boundary is not reread as part of the chain, so each is checked on
    /// its own before its material is cached: the next record names it as
    /// parent, and it carries the epoch its height says it ends.
    pub(super) fn restore_epochs_before(&self, end: u64, light: &LightBlockIndex) -> Result<()> {
        let length = light.epoch_length().get();
        let last = end / length;
        let first = last.saturating_sub(MAX_CACHED_EPOCHS as u64 - 1).max(1);
        // Genesis is the boundary before epoch one when an epoch is one block long.
        for height in (first..=last)
            .map(|epoch| epoch * length - 1)
            .filter(|&h| h > 0)
        {
            let bytes = self
                .db
                .get(key(RECORD, height))?
                .context("missing finalized epoch boundary; restore a complete node backup")?;
            let (block, _) = borsh::from_slice::<Record>(&bytes)?.decode()?;
            ensure!(block.height == height, "epoch boundary height mismatch");
            let next = self
                .db
                .get(key(RECORD, height + 1))?
                .context("missing finalized execution history; restore a complete node backup")?;
            let (child, _) = borsh::from_slice::<Record>(&next)?.decode()?;
            ensure!(
                child.height == height + 1 && child.parent == block.id(),
                "finalized history ancestry mismatch"
            );
            if let Some(Payload::EpochInfo(info)) = &block.payload {
                ensure!(
                    info.epoch.get() == (height + 1) / length,
                    "epoch boundary names another epoch"
                );
            }
            restore_epoch(light, &block);
        }
        Ok(())
    }
}
