//! Settings for a node hosted inside another program.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use vera_config::PruningConfig;

use super::{ThreadBudget, ThreadSetup};
use crate::{HistoryMemory, NodeSizing, SoloGenesis, SoloPacing};

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
    /// Retention of consensus archives and state journals. `None` retains all of both.
    ///
    /// Finalized history, which serves receipts, is kept in full either way.
    pub pruning: Option<PruningConfig>,
    /// Proposal pacing for the lone validator. `None` keeps the daemon's cadence.
    pub pacing: Option<SoloPacing>,
    /// Async worker threads of the node's runtime. `None` uses the runtime default.
    pub worker_threads: Option<usize>,
    /// Upper bound on the node runtime's blocking threads. `None` uses the runtime default.
    pub max_blocking_threads: Option<usize>,
    /// Threads of the pool that verifies native requests and digests blocks.
    ///
    /// The default depends on the machine, so `new` resolves it and
    /// [`Self::thread_budget`] reports the number that will run.
    pub verification_threads: usize,
    /// Runs on the node thread before any other thread of the node exists.
    pub thread_setup: Option<ThreadSetup>,
    /// Byte budgets of the finalized-history store.
    pub history_memory: HistoryMemory,
    /// Sizes of the allocations made at start.
    pub sizing: NodeSizing,
}

impl EmbeddedConfig {
    /// Default retention: two epochs of consensus archives and one of state journals.
    ///
    /// A lone validator has no peer to serve older consensus data to, and an
    /// idle one would otherwise add about 5 KiB to its directory per heartbeat.
    pub const RETENTION: PruningConfig = PruningConfig {
        maintenance_interval: std::num::NonZeroUsize::new(64).unwrap(),
        retained_consensus_revisions: 512,
        retained_state_revisions: 256,
    };

    /// Defaults for a lone validator: quiet when idle, with timeouts ordered below the genesis stall timeout.
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, genesis: SoloGenesis, p2p_listen: SocketAddr) -> Self {
        Self {
            data_dir: data_dir.into(),
            genesis,
            p2p_listen,
            rpc_listen: None,
            leader_timeout: Duration::from_secs(3),
            certification_timeout: Duration::from_secs(4),
            timeout_retry: Duration::from_millis(500),
            pruning: Some(Self::RETENTION),
            pacing: Some(SoloPacing::within(
                Duration::from_secs(3),
                Duration::from_millis(vera_domain::SimplexParameters::default().stall_timeout_ms),
            )),
            worker_threads: None,
            max_blocking_threads: None,
            verification_threads: crate::options::default_verification_threads().get(),
            thread_setup: None,
            history_memory: HistoryMemory::EMBEDDED,
            sizing: NodeSizing::EMBEDDED,
        }
    }

    /// The threads a node started with this configuration creates.
    #[must_use]
    pub fn thread_budget(&self) -> ThreadBudget {
        let runtime = commonware_runtime::tokio::Config::default();
        ThreadBudget {
            node: 1,
            workers: self.worker_threads.unwrap_or(runtime.worker_threads()),
            max_blocking: self
                .max_blocking_threads
                .unwrap_or(runtime.max_blocking_threads()),
            verification: self.verification_threads,
            history: crate::history::BACKGROUND_THREADS,
        }
    }
}
