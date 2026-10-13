/// Process-local Regolith counters; each field is sampled independently.
#[derive(Clone, Copy)]
pub(crate) struct HistoryWriteStatistics {
    pub(super) batch_input_bytes: u64,
    pub(super) wal_bytes: u64,
    pub(super) wal_syncs: u64,
    pub(super) flush_bytes: u64,
    pub(super) compaction_bytes: u64,
    pub(super) admitted_stall_us: u64,
}

impl std::fmt::Debug for HistoryWriteStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryWriteStatistics")
            .field("batch_input_bytes", &self.batch_input_bytes)
            .field("wal_bytes", &self.wal_bytes)
            .field("wal_syncs", &self.wal_syncs)
            .field("flush_bytes", &self.flush_bytes)
            .field("compaction_bytes", &self.compaction_bytes)
            .field("admitted_stall_us", &self.admitted_stall_us)
            .finish()
    }
}

impl HistoryWriteStatistics {
    pub(super) fn sample(statistics: &regolith::Statistics) -> Self {
        use regolith::Ticker;

        Self {
            batch_input_bytes: statistics.get_ticker(Ticker::BytesWritten),
            wal_bytes: statistics.get_ticker(Ticker::WalBytesWritten),
            wal_syncs: statistics.get_ticker(Ticker::WalSyncCount),
            flush_bytes: statistics.get_ticker(Ticker::FlushBytesWritten),
            compaction_bytes: statistics.get_ticker(Ticker::CompactionBytesWritten),
            admitted_stall_us: statistics.get_ticker(Ticker::WriteStallMicros),
        }
    }
}
