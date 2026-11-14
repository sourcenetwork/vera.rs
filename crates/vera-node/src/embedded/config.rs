//! Settings for a node hosted inside another program.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use vera_config::PruningConfig;

use super::{ThreadBudget, ThreadSetup};
use crate::{HistoryMemory, SoloGenesis, SoloPacing};

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
}

impl EmbeddedConfig {
    /// Default interval between the empty blocks an idle deployment finalizes.
    ///
    /// A client that verifies state against finalized headers refuses a state
    /// older than its freshness limit, 30 seconds in Backbone's light client,
    /// so an idle deployment cannot stop finalizing altogether.
    pub const HEARTBEAT: Duration = Duration::from_secs(10);

    /// Defaults for a lone validator: quiet when idle, with timeouts ordered below the genesis stall timeout.
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, genesis: SoloGenesis, p2p_listen: SocketAddr) -> Self {
        Self {
            data_dir: data_dir.into(),
            genesis,
            p2p_listen,
            rpc_listen: None,
            leader_timeout: Duration::from_secs(12),
            certification_timeout: Duration::from_secs(13),
            timeout_retry: Duration::from_millis(500),
            pruning: None,
            pacing: Some(SoloPacing {
                idle: Self::HEARTBEAT,
                batch: SoloPacing::BATCH,
            }),
            worker_threads: None,
            max_blocking_threads: None,
            verification_threads: crate::options::default_verification_threads().get(),
            thread_setup: None,
            history_memory: HistoryMemory::EMBEDDED,
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
