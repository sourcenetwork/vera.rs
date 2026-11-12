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
}

impl NodeOptions {
    /// The standalone daemon's behavior.
    #[must_use]
    pub const fn daemon(listener: Option<std::net::TcpListener>) -> Self {
        Self {
            rpc: RpcMode::Network(listener),
            watchdog: WatchdogMode::ExitProcess,
            ready: None,
        }
    }
}
