//! Memory the finalized-history store may hold for reads and unflushed writes.

/// Byte budgets of the finalized-history store.
///
/// They bound what the store keeps for itself. A record larger than the write
/// buffer is still accepted and is held in memory until it is flushed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryMemory {
    /// Decompressed table blocks kept for later reads. Zero keeps none.
    pub block_cache_bytes: usize,
    /// Written records held in memory before a flush moves them to a table.
    pub write_buffer_bytes: usize,
}

impl HistoryMemory {
    /// Budgets for a node hosted inside another program.
    pub const EMBEDDED: Self = Self {
        block_cache_bytes: 8 << 20,
        write_buffer_bytes: 4 << 20,
    };

    /// Why the store would refuse to open with these budgets.
    pub(crate) const fn rejection(&self) -> Option<&'static str> {
        if self.write_buffer_bytes == 0 {
            Some("history write buffer must be nonzero")
        } else {
            None
        }
    }
}
