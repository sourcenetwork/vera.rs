//! Host-facing choices for how a node serves RPC and reports a finality stall.

use vera_jsonrpc::LocalRpc;

/// Where the node's RPC methods are reachable.
#[derive(Debug)]
pub enum RpcMode {
    /// Serve the configured address, optionally through a prebound listener.
    Network(Option<std::net::TcpListener>),
    /// Bind no RPC socket; methods are reachable in-process only.
    Local,
}

/// What a tripped finality watchdog does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogMode {
    /// Exit the process so a supervisor can restart it.
    ExitProcess,
    /// Stop the node with an error and leave the process running.
    Report,
}

/// Options for a node hosted by another program.
#[derive(Debug)]
pub struct NodeOptions {
    /// RPC exposure.
    pub rpc: RpcMode,
    /// Finality-stall handling.
    pub watchdog: WatchdogMode,
    /// Receives the in-process method table once startup recovery has completed.
    pub ready: Option<tokio::sync::oneshot::Sender<LocalRpc>>,
    /// Proposal pacing for a deployment whose only validator is this node.
    pub solo_pacing: Option<SoloPacing>,
    /// Threads of the verification pool. `None` uses the machine's parallelism, at most four.
    pub verification_threads: Option<std::num::NonZeroUsize>,
}

/// Verification parallelism when the host does not choose one.
pub(crate) fn default_verification_threads() -> std::num::NonZeroUsize {
    const LIMIT: std::num::NonZeroUsize = std::num::NonZeroUsize::new(4).unwrap();
    std::thread::available_parallelism()
        .map_or(std::num::NonZeroUsize::MIN, |machine| machine.min(LIMIT))
}

/// How a lone validator paces proposals in pipelined mode.
///
/// `idle` must stay below the leader timeout and the genesis stall timeout,
/// or the validator abandons its own views.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoloPacing {
    /// Longest wait for a first request before proposing an empty block.
    pub idle: std::time::Duration,
    /// Window for collecting further requests once one has arrived.
    pub batch: std::time::Duration,
}

impl SoloPacing {
    /// Default batching window.
    ///
    /// Shorter windows propose empty blocks faster than they are durably committed,
    /// which delays the receipts of real requests. See `docs/embedded-node.md`.
    pub const BATCH: std::time::Duration = std::time::Duration::from_millis(50);

    /// Half of the tighter of the two timeouts that an idle proposer must not exceed.
    #[must_use]
    pub fn within(leader_timeout: std::time::Duration, stall_timeout: std::time::Duration) -> Self {
        Self {
            idle: leader_timeout.min(stall_timeout) / 2,
            batch: Self::BATCH,
        }
    }
}

impl NodeOptions {
    /// The standalone daemon's behavior.
    #[must_use]
    pub const fn daemon(listener: Option<std::net::TcpListener>) -> Self {
        Self {
            rpc: RpcMode::Network(listener),
            watchdog: WatchdogMode::ExitProcess,
            ready: None,
            solo_pacing: None,
            verification_threads: None,
        }
    }
}
