//! A validator hosted inside another program.
//!
//! The node runs on its own thread and Commonware runtime, so the host needs no
//! particular async runtime. Stopping drops that runtime; durability relies on
//! the same recovery path as an interrupted daemon.

mod config;
mod error;

use std::{net::SocketAddr, thread::JoinHandle};

use commonware_runtime::Runner as _;
use tokio::sync::oneshot;
use vera_config::{NetworkConfig, NodeConfig};
use vera_domain::ConsensusPublicKey;
use vera_genesis::VeraGenesis;
use vera_jsonrpc::LocalRpc;

pub use config::EmbeddedConfig;
pub use error::EmbedError;

use crate::{NodeOptions, NodeSettings, RpcMode, WatchdogMode};

/// The node's root future is polled on this thread and needs more than a spawned thread's default stack.
const NODE_STACK_BYTES: usize = 16 * 1024 * 1024;

/// A running embedded node.
#[derive(Debug)]
pub struct EmbeddedNode {
    rpc: LocalRpc,
    genesis: VeraGenesis,
    consensus_key: ConsensusPublicKey,
    stop: Option<oneshot::Sender<()>>,
    exit: oneshot::Receiver<Result<(), String>>,
    thread: Option<JoinHandle<()>>,
}

impl EmbeddedNode {
    /// Create or reopen the deployment and return once the node serves requests.
    pub async fn start(config: EmbeddedConfig) -> Result<Self, EmbedError> {
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
        if config.worker_threads == Some(0) || config.max_blocking_threads == Some(0) {
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
        let (stop_tx, stop_rx) = oneshot::channel();
        let (exit_tx, mut exit_rx) = oneshot::channel();
        let options = NodeOptions {
            rpc: match config.rpc_listen {
                Some(_) => RpcMode::Network(None),
                None => RpcMode::Local,
            },
            watchdog: WatchdogMode::Report,
            ready: Some(ready_tx),
            solo_pacing: config.pacing,
        };
        let (worker_threads, max_blocking_threads) =
            (config.worker_threads, config.max_blocking_threads);
        let storage = config.data_dir.join("commonware");
        std::fs::create_dir_all(&storage).map_err(|source| crate::SoloError::Io {
            path: storage.clone(),
            source,
        })?;
        let thread = std::thread::Builder::new()
            .name("vera-node".into())
            .stack_size(NODE_STACK_BYTES)
            .spawn(move || {
                let mut runtime =
                    commonware_runtime::tokio::Config::default().with_storage_directory(storage);
                if let Some(threads) = worker_threads {
                    runtime = runtime.with_worker_threads(threads);
                }
                if let Some(threads) = max_blocking_threads {
                    runtime = runtime.with_max_blocking_threads(threads);
                }
                let result =
                    commonware_runtime::tokio::Runner::new(runtime).start(|context| async move {
                        ::tokio::select! {
                            result = crate::run_node_with_options(context, settings, options) => {
                                Err(result.map_or_else(
                                    |error| format!("{error:#}"),
                                    |()| "node actors exited".into(),
                                ))
                            }
                            _ = stop_rx => Ok(()),
                        }
                    });
                // A host that dropped the node no longer observes the outcome.
                let _ = exit_tx.send(result);
            })
            .map_err(EmbedError::Thread)?;
        let rpc = ::tokio::select! {
            ready = ready_rx => ready.ok(),
            _ = &mut exit_rx => None,
        };
        let Some(rpc) = rpc else {
            return Err(outcome(exit_rx, thread)
                .await
                .err()
                .unwrap_or(EmbedError::Panicked));
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
            Ok(Err(reason)) => EmbedError::Stopped(reason),
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
        outcome(exit, thread).await
    }
}

impl Drop for EmbeddedNode {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn outcome(
    exit: oneshot::Receiver<Result<(), String>>,
    thread: JoinHandle<()>,
) -> Result<(), EmbedError> {
    let result = exit.await;
    // The thread has sent its result or is unwinding, so this join is brief.
    let joined = thread.join();
    match (result, joined) {
        (Ok(Ok(())), Ok(())) => Ok(()),
        (Ok(Err(reason)), Ok(())) => Err(EmbedError::Stopped(reason)),
        _ => Err(EmbedError::Panicked),
    }
}
