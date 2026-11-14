//! A validator hosted inside another program.
//!
//! The node runs on its own thread and Commonware runtime, so the host needs no
//! particular async runtime. Stopping drops that runtime; durability relies on
//! the same recovery path as an interrupted daemon.

mod config;
mod directory;
mod error;
mod thread_budget;
mod thread_setup;

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    thread::JoinHandle,
};

use commonware_runtime::Runner as _;
use tokio::sync::oneshot;
use vera_config::{NetworkConfig, NodeConfig};
use vera_domain::ConsensusPublicKey;
use vera_genesis::VeraGenesis;
use vera_jsonrpc::LocalRpc;

pub use config::EmbeddedConfig;
pub use error::EmbedError;
pub use thread_budget::ThreadBudget;
pub use thread_setup::ThreadSetup;

use crate::{NodeOptions, NodeSettings, RpcMode, WatchdogMode};

/// The node's root future is polled on this thread and needs more than a spawned thread's default stack.
const NODE_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Longest a stop waits for the blocks already proposed to finalize.
///
/// A block normally finalizes within a few hundred milliseconds. A stop that
/// gives up here is recovered like an interruption.
const STOP_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// A running embedded node.
#[derive(Debug)]
pub struct EmbeddedNode {
    rpc: LocalRpc,
    genesis: VeraGenesis,
    consensus_key: ConsensusPublicKey,
    stop: Option<oneshot::Sender<()>>,
    exit: oneshot::Receiver<Result<(), EmbedError>>,
    thread: Option<JoinHandle<()>>,
}

impl EmbeddedNode {
    /// Create or reopen the deployment and return once the node serves requests.
    pub async fn start(config: EmbeddedConfig) -> Result<Self, EmbedError> {
        launch(config).await
    }

    async fn launch(config: EmbeddedConfig) -> Result<Self, EmbedError> {
        let threads = config.thread_budget();
        if let Some(reason) = config.history_memory.rejection() {
            return Err(EmbedError::Config(reason));
        }
        let node_config = NodeConfig {
            chain_id: config.genesis.chain_id,
            data_dir: config.data_dir.clone(),
            network: NetworkConfig {
                listen_addr: config.p2p_listen.to_string(),
                ..NetworkConfig::default()
            },
            pruning: config.pruning,
            ..NodeConfig::default()
        };
        let (genesis, peers) = crate::prepare_solo(&node_config, &config.genesis)?;
        let consensus_key = *genesis
            .decode_epoch_info()
            .map_err(|error| crate::SoloError::Genesis(error.to_string()))?
            .ok_or_else(|| crate::SoloError::Genesis("missing epoch information".into()))?
            .output
            .public()
            .public();
        let stall_timeout_ms = genesis
            .simplex
            .map_or(u64::MAX, |parameters| parameters.stall_timeout_ms);
        let verification_threads = std::num::NonZeroUsize::new(threads.verification);
        if threads.workers == 0 || threads.max_blocking == 0 || verification_threads.is_none() {
            return Err(EmbedError::Config("thread counts must be nonzero"));
        }
        // Simplex requires this ordering and aborts its engine otherwise.
        if config.leader_timeout.is_zero()
            || config.certification_timeout <= config.leader_timeout
            || u128::from(stall_timeout_ms) <= config.certification_timeout.as_millis()
        {
            return Err(EmbedError::Config(
                "timeouts must satisfy 0 < leader < certification < genesis stall timeout",
            ));
        }
        if config
            .pacing
            .is_some_and(|pacing| pacing.idle >= config.leader_timeout)
        {
            return Err(EmbedError::Config(
                "idle wait must be shorter than the leader timeout",
            ));
        }
        let settings = NodeSettings {
            secrets_path: node_config.data_dir.join("secrets.json"),
            config: node_config,
            genesis: genesis.clone(),
            peers,
            // Unused unless `rpc_listen` is set.
            rpc_addr: config
                .rpc_listen
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0))),
            leader_timeout: config.leader_timeout,
            certification_timeout: config.certification_timeout,
            timeout_retry: config.timeout_retry,
        };
        let (ready_tx, ready_rx) = oneshot::channel();
        let (table_tx, table_rx) = oneshot::channel::<LocalRpc>();
        let (stop_tx, stop_rx) = oneshot::channel();
        let (exit_tx, mut exit_rx) = oneshot::channel();
        let hold = crate::ProposalHold::default();
        let options = NodeOptions {
            rpc: match config.rpc_listen {
                Some(_) => RpcMode::Network(None),
                None => RpcMode::Local,
            },
            watchdog: WatchdogMode::Report,
            ready: Some(table_tx),
            solo_pacing: config.pacing,
            verification_threads,
            history_memory: Some(config.history_memory),
            sizing: config.sizing,
            hold: Some(hold.clone()),
        };
        let thread_setup = config.thread_setup;
        let storage = config.data_dir.join("commonware");
        std::fs::create_dir_all(&storage).map_err(|source| crate::SoloError::Io {
            path: storage.clone(),
            source,
        })?;
        directory::refuse_held(&storage)?;
        let thread = std::thread::Builder::new()
            .name("vera-node".into())
            .stack_size(NODE_STACK_BYTES)
            .spawn(move || {
                // Threads take their placement from their creator, so the setup precedes the runtime.
                if let Some(setup) = thread_setup
                    && let Err(error) = setup.run()
                {
                    let _ = exit_tx.send(Err(EmbedError::ThreadSetup(error)));
                    return;
                }
                let runtime = commonware_runtime::tokio::Config::default()
                    .with_storage_directory(storage)
                    .with_worker_threads(threads.workers)
                    .with_max_blocking_threads(threads.max_blocking);
                let table = Arc::new(OnceLock::new());
                let served = table.clone();
                let result =
                    commonware_runtime::tokio::Runner::new(runtime).start(|context| async move {
                        ::tokio::spawn(async move {
                            if let Ok(rpc) = table_rx.await {
                                let _ = served.set(rpc.clone());
                                let _ = ready_tx.send(rpc);
                            }
                        });
                        let stopped = |result: anyhow::Result<()>| {
                            Err(EmbedError::Stopped(result.map_or_else(
                                |error| format!("{error:#}"),
                                |()| "node actors exited".into(),
                            )))
                        };
                        let mut node = std::pin::pin!(crate::run_node_with_options(
                            context, settings, options
                        ));
                        ::tokio::select! {
                            result = &mut node => return stopped(result),
                            _ = stop_rx => {}
                        }
                        // The node keeps running until the views in flight have finalized.
                        ::tokio::select! {
                            result = &mut node => stopped(result),
                            _ = hold.settle(STOP_SETTLE) => Ok(()),
                        }
                    });
                // The table holds the node's state, and that state holds the directory.
                // A host's clone may outlive the node, so the directory is freed here.
                if let Some(rpc) = table.get() {
                    rpc.close();
                }
                // A host that dropped the node no longer observes the outcome.
                let _ = exit_tx.send(result);
            })
            .map_err(EmbedError::Thread)?;
        // A received exit must not be awaited again: a completed receiver panics when polled.
        let started = ::tokio::select! {
            ready = ready_rx => ready.map_err(|_| None),
            exit = &mut exit_rx => Err(Some(exit)),
        };
        let rpc = match started {
            Ok(rpc) => rpc,
            Err(exit) => {
                let exit = match exit {
                    Some(exit) => exit,
                    None => exit_rx.await,
                };
                return Err(joined(exit, thread).err().unwrap_or(EmbedError::Panicked));
            }
        };
        Ok(Self {
            rpc,
            genesis,
            consensus_key,
            stop: Some(stop_tx),
            exit: exit_rx,
            thread: Some(thread),
        })
    }

    /// The node's methods, callable without a socket.
    #[must_use]
    pub const fn rpc(&self) -> &LocalRpc {
        &self.rpc
    }

    /// The deployment's genesis.
    #[must_use]
    pub const fn genesis(&self) -> &VeraGenesis {
        &self.genesis
    }

    /// The consensus key that finality proofs from this deployment verify against.
    #[must_use]
    pub const fn consensus_key(&self) -> &ConsensusPublicKey {
        &self.consensus_key
    }

    /// Wait until the node stops on its own, which is always an error.
    pub async fn failed(&mut self) -> EmbedError {
        match (&mut self.exit).await {
            Ok(Err(error)) => error,
            Ok(Ok(())) | Err(_) => EmbedError::Panicked,
        }
    }

    /// Stop the node and wait for its thread to finish.
    pub async fn stop(mut self) -> Result<(), EmbedError> {
        if let Some(stop) = self.stop.take() {
            // The node may already have stopped by itself.
            let _ = stop.send(());
        }
        let thread = self.thread.take().ok_or(EmbedError::Panicked)?;
        let exit = std::mem::replace(&mut self.exit, oneshot::channel().1);
        joined(exit.await, thread)
    }
}

impl Drop for EmbeddedNode {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// Builds the start future in this crate.
///
/// A host that instantiated it would compute the layout of the whole actor
/// graph and need a raised recursion limit; here it sees only a pointer.
#[inline(never)]
fn launch(
    config: EmbeddedConfig,
) -> Pin<Box<dyn Future<Output = Result<EmbeddedNode, EmbedError>> + Send>> {
    Box::pin(EmbeddedNode::launch(config))
}

fn joined(
    exit: Result<Result<(), EmbedError>, oneshot::error::RecvError>,
    thread: JoinHandle<()>,
) -> Result<(), EmbedError> {
    // The thread has sent its result or is unwinding, so this join is brief.
    match (exit, thread.join()) {
        (Ok(result), Ok(())) => result,
        _ => Err(EmbedError::Panicked),
    }
}
