//! Removing the records left below the floor's parent, in bounded batches.
//!
//! The `sweep` key holds the lowest height whose record may remain below
//! the floor's parent; absent, it is height 1. Every record below it is
//! gone, with its hash mappings. A batch reads the records from the cursor
//! up, removes the mappings that still name them and the records, and
//! advances the cursor, in one atomic write. A batch covers at most
//! [`BATCH`] heights and stops after the record that brings its mapping
//! deletes to [`MAPPING_DELETES`], so its size does not grow with the epoch
//! length or the submissions an epoch carries. A crash between batches
//! resumes from the cursor. The sweep never reaches the floor's parent.

use super::*;

pub(super) const SWEEP: &[u8] = b"sweep";
/// Most heights one batch sweeps.
const BATCH: u64 = 256;
/// Mapping deletes after which a batch ends.
const MAPPING_DELETES: usize = 4_096;

impl FinalizedHistory {
    /// The lowest height whose record may remain below the floor's parent.
    pub(super) fn sweep_cursor(&self) -> Result<u64> {
        match self.db.get(SWEEP)? {
            None => Ok(1),
            Some(bytes) => Ok(u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .context("invalid sweep cursor")?,
            )),
        }
    }

    /// Sweep up to `limit` heights below the floor's parent, one bounded
    /// batch at a time. Returns whether nothing is left to sweep.
    pub(super) fn sweep(
        &self,
        limit: u64,
        persist: &mut impl FnMut(&DB, WriteBatch) -> Result<()>,
    ) -> Result<bool> {
        let mut remaining = limit;
        loop {
            // Appends, cuts and recovery rewrite the hash mappings a batch reads.
            let _head = self.head.lock();
            let parent = self.floor_height()?.saturating_sub(1);
            let cursor = self.sweep_cursor()?;
            if cursor >= parent {
                return Ok(true);
            }
            if remaining == 0 {
                return Ok(false);
            }
            let end = parent.min(cursor.saturating_add(BATCH.min(remaining)));
            let mut batch = WriteBatch::default();
            let mut deleted = 0;
            let mut next = cursor;
            while next < end && deleted < MAPPING_DELETES {
                let record = self.record(next)?;
                deleted += self.unindex_pruned(&mut batch, next, &record)?;
                next += 1;
            }
            batch.delete_range(key(RECORD, cursor), key(RECORD, next));
            batch.put(SWEEP, next.to_be_bytes());
            persist(&self.db, batch)?;
            remaining -= next - cursor;
        }
    }
}
