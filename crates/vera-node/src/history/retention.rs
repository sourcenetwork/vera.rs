//! Removing the finalized records below a retained window.
//!
//! A prune moves the floor up in batches. Each batch is one atomic write: it
//! removes the records below the new floor, the certificates and imported
//! finality stored with them and the hash mappings they own, and stores the
//! new floor. A crash between batches leaves the floor of the last batch
//! written, which matches the records present.
//!
//! The records of epoch boundaries stay below the floor: the last block of
//! each epoch, whose artifact carries the next epoch's verifier material and
//! roster, and the first block of the next epoch, which a start reads to
//! check the boundary it follows. Light-block assembly reads the former for
//! an epoch whose material is not cached, `consensus_roster` reads it for an
//! older epoch's roster, and `restore_epochs_before` reads both.

use std::num::NonZeroU64;

use super::*;

/// Heights one batch removes.
const BATCH: u64 = 256;
/// Most heights one maintenance pass removes; a larger backlog is worked off
/// over later passes instead of holding up one finalization.
const PASS: u64 = 4 * BATCH;

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

/// Whether the record at `height` stays when the floor rises above it.
pub(super) const fn kept_below_floor(height: u64, epoch_length: NonZeroU64) -> bool {
    let length = epoch_length.get();
    height.is_multiple_of(length) || (height + 1).is_multiple_of(length)
}

impl FinalizedHistory {
    /// One maintenance pass: raise the floor towards `retained` revisions
    /// below the head, by at most a bounded number of heights.
    pub(crate) fn maintain(&self, retention: &HistoryRetention) -> Result<u64> {
        let floor = self.floor_height()?;
        let Some(target) = self.head_height().checked_sub(retention.retained) else {
            return Ok(floor);
        };
        self.prune_below(
            target.min(floor.saturating_add(PASS)),
            retention.epoch_length,
        )
    }

    /// Remove the records below `target`, which becomes the floor, keeping
    /// the epoch boundaries. The head is never removed, and a target at or
    /// below the floor changes nothing. Returns the floor.
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
            let target = target.min(head.0);
            if target <= floor {
                return Ok(floor);
            }
            ensure!(
                self.db.get(transfer::IMPORT)?.is_none(),
                "history import is pending"
            );
            let next = target.min(floor.saturating_add(BATCH));
            let mut batch = WriteBatch::default();
            let mut removed = None;
            for height in floor..next {
                let record = self.record(height)?;
                self.unindex_pruned(&mut batch, height, &record)?;
                if kept_below_floor(height, epoch_length) {
                    if let Some(start) = removed.take() {
                        batch.delete_range(key(RECORD, start), key(RECORD, height));
                    }
                } else {
                    removed.get_or_insert(height);
                }
            }
            if let Some(start) = removed {
                batch.delete_range(key(RECORD, start), key(RECORD, next));
            }
            for prefix in [CERTIFICATE, IMPORTED_FINALITY, PROOF_BLOCK] {
                batch.delete_range(key(prefix, floor), key(prefix, next));
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
#[path = "retention_tests.rs"]
mod tests;
