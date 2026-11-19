//! Removing the finalized records below a retained window.
//!
//! The floor is the first block of an epoch, or height 1 while nothing is
//! pruned. The store holds one contiguous run of records from the block
//! before the floor through the head. That block, the last of the previous
//! epoch, is the floor's parent and carries the verifier material of the
//! floor's epoch, which light-block assembly and a start read. Nothing else
//! is kept below the floor.
//!
//! A prune raises the floor one epoch per batch. Each batch is one atomic
//! write: it removes the records below the new floor's parent, the
//! certificates, imported finality and proof blocks below the new floor, and
//! the hash mappings of every record below it, and stores the new floor. A
//! crash between batches leaves the floor of the last batch written, which
//! matches the records present.

use std::num::NonZeroU64;

use super::*;

/// Most heights one maintenance pass removes, rounded up to whole epochs; a
/// larger backlog is worked off over later passes instead of holding up one
/// finalization.
const PASS: u64 = 1_024;

/// Finalized revisions between maintenance passes when consensus pruning,
/// whose interval history otherwise shares, is not configured.
pub const HISTORY_MAINTENANCE_INTERVAL: NonZeroU64 = NonZeroU64::new(64).unwrap();

/// A history retention shorter than the windows the node reads below its head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("history retention of {retained} revisions is below the minimum of {minimum}")]
pub struct RetentionTooShort {
    /// The configured retention.
    pub retained: u64,
    /// The smallest retention the deployment's epoch length allows.
    pub minimum: u64,
}

/// The fewest revisions below the head that history may retain: the
/// execution index's resident window, which a start rereads, the longest
/// suffix a recovery rewinds, and two epochs.
pub const fn minimum_history_retention(epoch_length: NonZeroU64) -> u64 {
    (MAX_CACHED_REVISIONS as u64)
        .saturating_add(rewind::MAX_SUFFIX)
        .saturating_add(epoch_length.get().saturating_mul(2))
}

/// Accept `retained` revisions of history for a deployment with `epoch_length`.
pub const fn check_history_retention(
    retained: u64,
    epoch_length: NonZeroU64,
) -> std::result::Result<(), RetentionTooShort> {
    let minimum = minimum_history_retention(epoch_length);
    if retained < minimum {
        return Err(RetentionTooShort { retained, minimum });
    }
    Ok(())
}

/// How a node keeps its finalized history bounded.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HistoryRetention {
    /// Revisions kept below the head.
    pub retained: u64,
    /// Finalized revisions between maintenance passes.
    pub interval: NonZeroU64,
    /// The deployment's fixed epoch length.
    pub epoch_length: NonZeroU64,
}

impl HistoryRetention {
    /// Whether the revision at `height` is followed by a maintenance pass.
    pub(crate) const fn due(&self, height: u64) -> bool {
        height.is_multiple_of(self.interval.get())
    }
}

/// The first block of the epoch holding `height`; 0 for the genesis epoch.
const fn epoch_start(height: u64, epoch_length: NonZeroU64) -> u64 {
    height - height % epoch_length.get()
}

impl FinalizedHistory {
    /// One maintenance pass: raise the floor towards `retained` revisions
    /// below the head, by a bounded number of epochs. A pending import is
    /// left alone; the pass returns the floor unchanged.
    pub(crate) fn maintain(&self, retention: &HistoryRetention) -> Result<u64> {
        let floor = self.floor_height()?;
        if self.db.get(transfer::IMPORT)?.is_some() {
            return Ok(floor);
        }
        let Some(target) = self.head_height().checked_sub(retention.retained) else {
            return Ok(floor);
        };
        let pass = PASS.max(retention.epoch_length.get());
        self.prune_below(
            target.min(floor.saturating_add(pass)),
            retention.epoch_length,
        )
    }

    /// Raise the floor to the first block of the epoch holding `target`, so
    /// at least the revisions from `target` stay, and remove what lies below
    /// the floor's parent. The head's epoch stays, and a target at or below
    /// the floor changes nothing. Returns the floor.
    pub fn prune_below(&self, target: u64, epoch_length: NonZeroU64) -> Result<u64> {
        self.prune_below_with(target, epoch_length, write)
    }

    pub(super) fn prune_below_with(
        &self,
        target: u64,
        epoch_length: NonZeroU64,
        mut persist: impl FnMut(&DB, WriteBatch) -> Result<()>,
    ) -> Result<u64> {
        loop {
            // Appends, cuts and recovery rewrite the hash mappings this batch reads.
            let head = self.head.lock();
            let floor = self.floor_height()?;
            let target = epoch_start(target.min(head.0), epoch_length);
            if target <= floor {
                return Ok(floor);
            }
            ensure!(
                self.db.get(transfer::IMPORT)?.is_none(),
                "history import is pending"
            );
            let next = epoch_start(floor, epoch_length) + epoch_length.get();
            let lowest = floor.saturating_sub(1).max(1);
            let mut batch = WriteBatch::default();
            for height in lowest..next {
                let record = self.record(height)?;
                self.unindex_pruned(&mut batch, height, &record)?;
            }
            batch.delete_range(key(RECORD, 0), key(RECORD, next - 1));
            for prefix in [CERTIFICATE, IMPORTED_FINALITY, PROOF_BLOCK] {
                batch.delete_range(key(prefix, 0), key(prefix, next));
            }
            let id = alloy_primitives::keccak256(&self.record(next)?.block);
            batch.put(FLOOR, borsh::to_vec(&(next, id.0))?);
            persist(&self.db, batch)?;
        }
    }

    /// Stage removing the mappings that point at the record at `height`.
    /// A submission hash a later revision repeats maps to that revision and stays.
    fn unindex_pruned(&self, batch: &mut WriteBatch, height: u64, record: &Record) -> Result<()> {
        let id = alloy_primitives::keccak256(&record.block);
        let mut unindex = |prefix, hash: &[u8; 32]| -> Result<()> {
            let key = query::hash_key(prefix, hash);
            if self.db.get(key)?.as_deref() == Some(height.to_be_bytes().as_slice()) {
                batch.delete(key);
            }
            Ok(())
        };
        unindex(BLOCK_HASH, &id.0)?;
        for receipt in &record.receipts {
            unindex(SUBMISSION_HASH, &receipt.hash)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "retention_fixture.rs"]
pub(super) mod fixture;

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "import_floor_tests.rs"]
mod import_tests;
