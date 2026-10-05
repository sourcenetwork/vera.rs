//! RPC event types emitted by the RPC poller.

/// Events from polling node RPC endpoints.
#[derive(Clone, Debug)]
pub enum RpcEvent {
    /// A new block was observed on a node.
    NewBlock {
        /// Node index.
        node: usize,
        /// Block height.
        height: u64,
    },
    /// Consensus view observation changed (including telemetry becoming unavailable).
    ViewAdvanced {
        /// Node index.
        node: usize,
        /// New view number, or unavailable telemetry.
        view: Option<u64>,
    },
    /// A block was finalized.
    Finalized {
        /// Node index.
        node: usize,
        /// Finalized count.
        count: u64,
    },
    /// Peer count changed for a node.
    PeerCountChanged {
        /// Node index.
        node: usize,
        /// New peer count, or unavailable telemetry.
        peers: Option<u64>,
    },
    /// Leader status changed for a node.
    LeaderChanged {
        /// Node index.
        node: usize,
        /// Whether this node is now the leader, if observed.
        is_leader: Option<bool>,
    },
}
