//! Starting the thread an embedded node runs on.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use commonware_runtime::Runner as _;
use tokio::sync::oneshot;
use vera_domain::{ConsensusPublicKey, PublicKey};
use vera_genesis::VeraGenesis;
use vera_jsonrpc::LocalRpc;

use super::{
    DeviceRole, EmbedError, EmbeddedConfig, directory, rpc_socket::RpcSocket, thread::NodeThread,
};
use crate::{
    NodeOptions, NodeSettings, RpcMode, SoloDeployment, TermRefusal, WatchdogMode,
    term::{TermControl, device_id},
};

/// The node's root future is polled on this thread and needs more than a spawned thread's default stack.
const NODE_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Longest a stop waits for the blocks already proposed to finalize.
///
/// A block normally finalizes within a few hundred milliseconds. A stop that
/// gives up here is recovered like an interruption.
const STOP_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// A node whose thread has started, with what its host reads from it.
#[derive(Debug)]
pub(super) struct Launched {
    pub(super) rpc_socket: Option<RpcSocket>,
    pub(super) genesis: VeraGenesis,
    pub(super) consensus_key: ConsensusPublicKey,
    pub(super) identity: PublicKey,
    pub(super) backup: bool,
    pub(super) data_dir: PathBuf,
    pub(super) deployment: Option<SoloDeployment>,
    pub(super) config: Box<EmbeddedConfig>,
    pub(super) term: TermControl,
    pub(super) thread: NodeThread,
}

/// Check `config`, claim its directory and start the node's thread.
///
/// Returns without waiting for the node: the receiver resolves with its
/// method table once it serves requests, and [`NodeThread::started`] waits
/// for that. The caller owns the thread from here on.
pub(super) fn launch(
    config: EmbeddedConfig,
    rpc_socket: Option<RpcSocket>,
) -> Result<(Launched, oneshot::Receiver<LocalRpc>), EmbedError> {
    let threads = config.thread_budget();
    if let Some(reason) = config.history_memory.rejection() {
        return Err(EmbedError::Config(reason));
    }
    let node_config = config.node_config();
    let configured = Box::new(config.clone());
    super::refuse_role(&config)?;
    if matches!(config.role, DeviceRole::Backup(_)) && config.deployment.is_some() {
        return Err(EmbedError::Config("a backup takes no key material"));
    }
    let (genesis, peers, backup) = match (&config.role, &config.deployment) {
        (DeviceRole::Backup(backup), _) => {
            let (genesis, peers) = crate::solo::follow_solo(
                &node_config,
                &config.genesis,
                &backup.record,
                backup.active,
            )?;
            let key = match (&backup.transport_key, &config.switching) {
                (Some(key), _) => key.clone(),
                (None, Some(switching)) => switching.device_key.clone(),
                (None, None) => crate::DeviceKey::load_or_create(&config.data_dir)?,
            };
            (genesis, peers, Some(key))
        }
        (DeviceRole::Active, Some(deployment)) => {
            let (genesis, peers) =
                crate::solo::adopt_solo(&node_config, &config.genesis, deployment)?;
            (genesis, peers, None)
        }
        (DeviceRole::Active, None) => {
            let (genesis, peers) = crate::prepare_solo(&node_config, &config.genesis)?;
            (genesis, peers, None)
        }
    };
    let is_backup = backup.is_some();
    let claim = directory::claim(&config.data_dir)?;
    // Nothing below may touch a directory another node runs on.
    let storage = config.data_dir.join("commonware");
    if storage.is_dir() {
        directory::refuse_held(&storage)?;
    }
    crate::term::settle_role(&config.data_dir, is_backup)?;
    if is_backup {
        let this = config
            .switching
            .as_ref()
            .map(|switching| device_id(&switching.device_key.public_key()));
        crate::term::rewind(&config.data_dir, this, config.history_memory)?;
    }
    let identity = backup.as_ref().map_or_else(
        || peers.participants[0].clone(),
        crate::DeviceKey::public_key,
    );
    let consensus_key = *genesis
        .decode_epoch_info()
        .map_err(|error| crate::SoloError::Genesis(error.to_string()))?
        .ok_or_else(|| crate::SoloError::Genesis("missing epoch information".into()))?
        .output
        .public()
        .public();
    let verification_threads = std::num::NonZeroUsize::new(threads.verification);
    if threads.workers == 0 || threads.max_blocking == 0 || verification_threads.is_none() {
        return Err(EmbedError::Config("thread counts must be nonzero"));
    }
    crate::consensus_timeouts::validate(
        config.leader_timeout,
        config.certification_timeout,
        config.timeout_retry,
        std::time::Duration::from_millis(genesis.simplex.stall_timeout_ms),
    )
    .map_err(|error| EmbedError::Config(error.reason()))?;
    if let (Some(retained), Some(epoch_length)) = (
        config.history_retention,
        std::num::NonZeroU64::new(genesis.blocks_per_epoch),
    ) {
        crate::check_history_retention(retained, epoch_length)?;
    }
    if config
        .pacing
        .is_some_and(|pacing| pacing.idle >= config.leader_timeout)
    {
        return Err(EmbedError::Config(
            "idle wait must be shorter than the leader timeout",
        ));
    }
    let rpc_socket = match (rpc_socket, config.rpc_listen) {
        (Some(socket), Some(_)) => Some(socket),
        (_, Some(address)) => Some(RpcSocket::bind(address)?),
        (_, None) => None,
    };
    let rpc = match &rpc_socket {
        Some(socket) => RpcMode::Network(Some(socket.share()?)),
        None => RpcMode::Local,
    };
    let settings = NodeSettings {
        secrets_path: node_config.data_dir.join("secrets.json"),
        config: node_config,
        genesis: genesis.clone(),
        peers,
        // Unused without a network listener.
        rpc_addr: rpc_socket
            .as_ref()
            .map_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)), RpcSocket::address),
        leader_timeout: config.leader_timeout,
        certification_timeout: config.certification_timeout,
        timeout_retry: config.timeout_retry,
    };
    let (ready_tx, ready_rx) = oneshot::channel();
    let (table_tx, table_rx) = oneshot::channel::<LocalRpc>();
    let (stop_tx, stop_rx) = oneshot::channel();
    let (exit_tx, exit_rx) = oneshot::channel();
    let hold = crate::ProposalHold::default();
    let (term, seat) = TermControl::new();
    let mut devices = config.backups;
    if let Some(switching) = &config.switching {
        devices.extend(switching.devices.iter().map(|device| device.key.clone()));
    }
    let options = NodeOptions {
        rpc,
        watchdog: WatchdogMode::Report,
        ready: Some(table_tx),
        solo_pacing: config.pacing,
        verification_threads,
        history_memory: Some(config.history_memory),
        sizing: config.sizing,
        hold: Some(hold.clone()),
        keys: config
            .deployment
            .as_ref()
            .map(|deployment| deployment.keys().clone()),
        // Backups do not connect to each other, and a peer that never
        // connects would still be asked for blocks and state.
        devices: if is_backup { Vec::new() } else { devices },
        backup,
        switching: config.switching,
        term: Some(seat),
    };
    let thread_setup = config.thread_setup;
    let data_dir = config.data_dir.clone();
    let deployment = config.deployment;
    let storage = config.data_dir.join("commonware");
    std::fs::create_dir_all(&storage).map_err(|source| crate::SoloError::Io {
        path: storage.clone(),
        source,
    })?;
    directory::refuse_held(&storage)?;
    let handle = std::thread::Builder::new()
        .name("vera-node".into())
        .stack_size(NODE_STACK_BYTES)
        .spawn(move || {
            // Threads take their placement from their creator, so the setup precedes the runtime.
            if let Some(setup) = thread_setup
                && let Err(error) = setup.run()
            {
                drop(claim);
                let _ = exit_tx.send(Err(EmbedError::ThreadSetup(error)));
                return;
            }
            let runtime = commonware_runtime::tokio::Config::default()
                .with_storage_directory(storage)
                .with_worker_threads(threads.workers)
                .with_max_blocking_threads(threads.max_blocking);
            let table = Arc::new(OnceLock::new());
            let served = table.clone();
            let decided = Arc::new(std::sync::Mutex::new(None));
            let recorded = decided.clone();
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                commonware_runtime::tokio::Runner::new(runtime).start(|context| async move {
                    ::tokio::spawn(async move {
                        if let Ok(rpc) = table_rx.await {
                            let _ = served.set(rpc.clone());
                            let _ = ready_tx.send(rpc);
                        }
                    });
                    let stopped = |result: anyhow::Result<()>| {
                        Err(match result {
                            Ok(()) => EmbedError::Stopped("node actors exited".into()),
                            Err(error) => match error.downcast::<TermRefusal>() {
                                Ok(refusal) => EmbedError::Term(refusal),
                                Err(error) => EmbedError::Stopped(format!("{error:#}")),
                            },
                        })
                    };
                    let mut node =
                        std::pin::pin!(crate::run_node_with_options(context, settings, options));
                    let result = async {
                        ::tokio::select! {
                            result = &mut node => return stopped(result),
                            _ = stop_rx => {}
                        }
                        // The node keeps running until the views in flight have finalized.
                        ::tokio::select! {
                            result = &mut node => stopped(result),
                            _ = hold.settle(STOP_SETTLE) => Ok(()),
                        }
                    }
                    .await;
                    *recorded
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
                });
            }));
            let decided = decided
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let result = ended(run.is_ok(), decided);
            // The table holds the node's state, and that state holds the directory.
            // A host's clone may outlive the node, so the directory is freed here.
            if let Some(rpc) = table.get() {
                rpc.close();
            }
            drop(claim);
            // A host that dropped the node no longer observes the outcome.
            let _ = exit_tx.send(result);
        })
        .map_err(EmbedError::Thread)?;
    let launched = Launched {
        rpc_socket,
        genesis,
        consensus_key,
        identity,
        backup: is_backup,
        data_dir,
        deployment,
        config: configured,
        term,
        thread: NodeThread::new(stop_tx, exit_rx, handle),
    };
    Ok((launched, ready_rx))
}

/// How a node ended, from whether its runtime unwound and the result its root
/// returned, if it returned.
///
/// Commonware aborts the node's tasks once the root has returned, and a task
/// that observes a sibling's abort can panic then. How the node ended was
/// decided before that.
fn ended(completed: bool, decided: Option<Result<(), EmbedError>>) -> Result<(), EmbedError> {
    let result = decided.ok_or(EmbedError::Panicked)?;
    if !completed {
        tracing::warn!("a node task panicked while the stopped node's runtime shut down");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_after_the_node_returned_keeps_how_it_ended() {
        let refusal = || Err(EmbedError::Term(TermRefusal::NotCertified));
        for completed in [true, false] {
            assert!(matches!(
                ended(completed, Some(refusal())),
                Err(EmbedError::Term(TermRefusal::NotCertified))
            ));
            assert!(matches!(ended(completed, Some(Ok(()))), Ok(())));
        }
        assert!(matches!(ended(false, None), Err(EmbedError::Panicked)));
    }
}
