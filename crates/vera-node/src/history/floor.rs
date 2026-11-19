//! The oldest revision finalized history retains.
//!
//! The `floor` key holds a height and block hash: every record from that
//! block through the head is present. Absent, the floor is the first block
//! after genesis. Only the batch that removes the records below a new floor
//! writes it, so the key always matches what the store holds.
//!
//! Below the floor the store keeps only the records of epoch boundaries
//! (see `retention`). They serve the epoch material and rosters read with
//! them; no reader serves them as revisions.

use super::*;

pub(super) const FLOOR: &[u8] = b"floor";

/// A read of a revision that finalized history no longer retains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("finalized history retains revisions from {floor}; revision {height} is pruned")]
pub struct HistoryPruned {
    /// The requested revision.
    pub height: u64,
    /// The oldest revision the store retains.
    pub floor: u64,
}

/// Height of the floor stored as `bytes`, the first block when absent.
pub(super) fn floor_height(bytes: Option<&[u8]>) -> Result<u64> {
    match bytes {
        None => Ok(1),
        Some(bytes) => Ok(borsh::from_slice::<(u64, [u8; 32])>(bytes)?.0),
    }
}

/// Fail with [`HistoryPruned`] when the revision at `height` is below `floor`.
pub(super) fn check_retained(height: u64, floor: u64) -> Result<()> {
    if height > 0 && height < floor {
        return Err(HistoryPruned { height, floor }.into());
    }
    Ok(())
}

/// Fail with [`HistoryPruned`] unless the store holds the block at `height`
/// to cut back to: genesis while nothing is pruned, or a retained record.
pub(super) fn check_cut(height: u64, floor: u64) -> Result<()> {
    if height < floor && !(height == 0 && floor == 1) {
        return Err(HistoryPruned { height, floor }.into());
    }
    Ok(())
}

impl FinalizedHistory {
    /// The oldest revision whose record is retained; 1 until the store is pruned.
    pub fn floor_height(&self) -> Result<u64> {
        floor_height(self.db.get(FLOOR)?.as_deref())
    }

    /// The stored floor with its block's hash, `None` until the store is pruned.
    pub(super) fn floor(&self) -> Result<Option<(u64, B256)>> {
        self.db
            .get(FLOOR)?
            .map(|bytes| {
                let (height, hash) = borsh::from_slice::<(u64, [u8; 32])>(&bytes)?;
                Ok((height, B256::from(hash)))
            })
            .transpose()
    }
}

impl From<HistoryPruned> for vera_jsonrpc::RpcError {
    fn from(pruned: HistoryPruned) -> Self {
        Self::HistoryPruned {
            height: pruned.height,
            floor: pruned.floor,
        }
    }
}

/// The RPC error for a failed history read: [`vera_jsonrpc::RpcError::HistoryPruned`]
/// below the floor, otherwise the one `other` makes of its message.
pub(crate) fn rpc_error(
    error: &anyhow::Error,
    other: impl FnOnce(String) -> vera_jsonrpc::RpcError,
) -> vera_jsonrpc::RpcError {
    error
        .downcast_ref::<HistoryPruned>()
        .map_or_else(|| other(error.to_string()), |pruned| (*pruned).into())
}
