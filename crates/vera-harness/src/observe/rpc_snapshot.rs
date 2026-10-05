//! Per-node RPC state snapshot.

/// Latest known state of a single node from RPC polling.
///
/// Block height comes from observed finalization in `vera_nodeStatus`, or from
/// `eth_getBlockByNumber` when no finalized observation is available. Process-local
/// callback counts are not block heights.
///
/// Use `effective_height()` to get the best available height.
#[derive(Clone, Debug, Default)]
pub struct NodeSnapshot {
    /// Node index in the cluster.
    pub node_index: usize,
    /// Chain ID reported by the node.
    pub chain_id: u64,
    /// Validator index reported by the node.
    pub validator_index: u32,
    /// Validator count from this node's startup configuration.
    pub validator_count: u32,
    /// Seconds since the node started.
    pub uptime_secs: u64,
    /// Current consensus view, if actual live telemetry is available.
    pub current_view: Option<u64>,
    /// Height of the latest observed finalized block.
    pub finalized_height: Option<u64>,
    /// Epoch of the latest observed finalization.
    pub finalized_epoch: Option<u64>,
    /// View of the latest observed finalization within its epoch.
    pub finalized_view: Option<u64>,
    /// Native snapshot revision installed on this node, if observed.
    pub snapshot_revision: Option<u64>,
    /// Finalized callbacks processed in this process, not chain height.
    pub finalized_count: u64,
    /// Proposals processed in this process.
    pub proposed_count: u64,
    /// Number of nullified rounds, if instrumented.
    pub nullified_count: Option<u64>,
    /// Number of connected peers, if instrumented.
    pub peer_count: Option<u64>,
    /// Whether this node is the current leader, if observed.
    pub is_leader: Option<bool>,
    /// Whether this node is backfilling historical blocks.
    pub backfilling: bool,
    /// Latest block height from eth_getBlockByNumber.
    pub latest_block_height: u64,
    /// Whether the node is reachable.
    pub is_healthy: bool,
}

impl NodeSnapshot {
    /// Best available block height.
    ///
    /// Prefers observed `finalized_height`, falling back to the indexed block
    /// height. Returns zero before either source reports progress.
    pub const fn effective_height(&self) -> u64 {
        match self.finalized_height {
            Some(height) => height,
            None => self.latest_block_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NodeSnapshot;

    #[test]
    fn progress_uses_observed_height_not_callback_count() {
        let mut snapshot = NodeSnapshot {
            finalized_count: 100,
            ..NodeSnapshot::default()
        };
        assert_eq!(snapshot.effective_height(), 0);
        snapshot.latest_block_height = 7;
        assert_eq!(snapshot.effective_height(), 7);
        snapshot.finalized_height = Some(6);
        assert_eq!(snapshot.effective_height(), 6);
    }
}
