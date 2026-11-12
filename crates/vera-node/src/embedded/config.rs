//! Settings for a node hosted inside another program.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use vera_config::PruningConfig;

use crate::SoloGenesis;

/// Configuration of an embedded single-validator node.
#[derive(Clone, Debug)]
pub struct EmbeddedConfig {
    /// Directory owned by this node. It must not be shared with another store.
    pub data_dir: PathBuf,
    /// Deployment identity, fixed when the directory is first used.
    pub genesis: SoloGenesis,
    /// Consensus network listener. A single validator dials no peers but still binds it.
    pub p2p_listen: SocketAddr,
    /// Network JSON-RPC listener. `None` exposes methods in-process only.
    pub rpc_listen: Option<SocketAddr>,
    /// Time a leader has to propose before the view is abandoned.
    pub leader_timeout: Duration,
    /// Time a proposal has to be certified before the view is abandoned.
    pub certification_timeout: Duration,
    /// Interval between repeated view-abandonment votes.
    pub timeout_retry: Duration,
    /// Consensus history pruning. `None` retains all history.
    pub pruning: Option<PruningConfig>,
}

impl EmbeddedConfig {
    /// Loopback-only defaults with the standalone daemon's consensus timeouts.
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, genesis: SoloGenesis, p2p_listen: SocketAddr) -> Self {
        Self {
            data_dir: data_dir.into(),
            genesis,
            p2p_listen,
            rpc_listen: None,
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_millis(500),
            pruning: None,
        }
    }
}
