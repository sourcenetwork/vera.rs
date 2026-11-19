//! Raising the floor below a retained window.
//!
//! The floor is the first block of an epoch, or height 1 while nothing is
//! pruned. The store serves the records from the floor through the head, and
//! keeps the floor's parent, the last block of the previous epoch, which
//! carries the verifier material of the floor's epoch that light-block
//! assembly and a start read.
//!
//! Raising the floor is one small atomic write: it stores the new floor,
//! removes every certificate, imported finality and proof block below it,
//! and the hash mappings of the new floor's parent. Readers refuse heights
//! below the floor from then on, and a mapping that still names one reads as
//! pruned. The records left below the floor's parent, and their mappings, are
//! removed afterwards in bounded batches (see `sweep`).

use std::num::NonZeroU64;

use super::*;

/// Most heights one maintenance pass sweeps; a larger backlog is worked off
/// over later passes instead of holding up one finalization.
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
    /// One maintenance pass: raise the floor to `retained` revisions below
    /// the head, then sweep at most a bounded number of heights below it. A
    /// pending import is left alone; the pass returns the floor unchanged.
    pub(crate) fn maintain(&self, retention: &HistoryRetention) -> Result<u64> {
        if self.db.get(transfer::IMPORT)?.is_some() {
            return self.floor_height();
        }
        let floor = match self.head_height().checked_sub(retention.retained) {
            Some(target) => self.raise_floor(target, retention.epoch_length, &mut write)?,
            None => self.floor_height()?,
        };
        self.sweep(PASS, &mut write)?;
        Ok(floor)
    }

    /// Raise the floor to the first block of the epoch holding `target`, so
    /// at least the revisions from `target` stay, and remove everything below
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
        let floor = self.raise_floor(target, epoch_length, &mut persist)?;
        while !self.sweep(u64::MAX, &mut persist)? {}
        Ok(floor)
    }

    /// Store the floor for `target` in one write, as described in the module.
    fn raise_floor(
        &self,
        target: u64,
        epoch_length: NonZeroU64,
        persist: &mut impl FnMut(&DB, WriteBatch) -> Result<()>,
    ) -> Result<u64> {
        // Appends, cuts and recovery rewrite the hash mappings this write reads.
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
        let mut batch = WriteBatch::default();
        for prefix in [CERTIFICATE, IMPORTED_FINALITY, PROOF_BLOCK] {
            batch.delete_range(key(prefix, 0), key(prefix, target));
        }
        let parent = self.record(target - 1)?;
        self.unindex_pruned(&mut batch, target - 1, &parent)?;
        let id = alloy_primitives::keccak256(&self.record(target)?.block);
        batch.put(FLOOR, borsh::to_vec(&(target, id.0))?);
        persist(&self.db, batch)?;
        Ok(target)
    }

    /// Stage removing the mappings that point at the record at `height`, and
    /// return how many there are.
    /// A submission hash a later revision repeats maps to that revision and stays.
    pub(super) fn unindex_pruned(
        &self,
        batch: &mut WriteBatch,
        height: u64,
        record: &Record,
    ) -> Result<usize> {
        let mut deleted = 0;
        let id = alloy_primitives::keccak256(&record.block);
        let mut unindex = |prefix, hash: &[u8; 32]| -> Result<()> {
            let key = query::hash_key(prefix, hash);
            if self.db.get(key)?.as_deref() == Some(height.to_be_bytes().as_slice()) {
                batch.delete(key);
                deleted += 1;
            }
            Ok(())
        };
        unindex(BLOCK_HASH, &id.0)?;
        for receipt in &record.receipts {
            unindex(SUBMISSION_HASH, &receipt.hash)?;
        }
        Ok(deleted)
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
