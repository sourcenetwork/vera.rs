//! A validator hosted inside another program.
//!
//! The node runs on its own thread and Commonware runtime, so the host needs no
//! particular async runtime. Stopping drops that runtime; durability relies on
//! the same recovery path as an interrupted daemon.

mod config;
mod directory;
mod error;
mod role;
mod thread_budget;
mod thread_setup;

use std::{
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock},
    thread::JoinHandle,
};

use commonware_runtime::Runner as _;
use tokio::sync::oneshot;
use vera_domain::{ConsensusPublicKey, PublicKey, TermCertificate, TermChange};
use vera_genesis::VeraGenesis;
use vera_jsonrpc::LocalRpc;

pub use config::EmbeddedConfig;
pub use error::EmbedError;
pub use role::{Backup, DeviceRole};
pub use thread_budget::ThreadBudget;
pub use thread_setup::ThreadSetup;

use crate::{
    DiscardedSubmission, NodeOptions, NodeSettings, RpcMode, SoloDeployment, SoloError, SoloKeys,
    TermRefusal, WatchdogMode,
    term::{Accept, TermControl, TermRecord, device_id},
};

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
    identity: PublicKey,
    backup: bool,
    data_dir: PathBuf,
    deployment: Option<SoloDeployment>,
    config: Box<EmbeddedConfig>,
    term: TermControl,
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
        let node_config = config.node_config();
        let configured = Box::new(config.clone());
        refuse_role(&config)?;
        let (genesis, peers, backup) = match (&config.role, &config.deployment) {
            (DeviceRole::Backup(_), Some(_)) => {
                return Err(EmbedError::Config("a backup takes no key material"));
            }
            (DeviceRole::Backup(backup), None) => {
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
        if config.switching.is_some() {
            // Nothing below may touch a directory another node runs on.
            let storage = config.data_dir.join("commonware");
            if storage.is_dir() {
                directory::refuse_held(&storage)?;
            }
            crate::term::settle_role(&config.data_dir, is_backup)?;
            if is_backup {
                crate::term::rewind(&config.data_dir, config.history_memory)?;
            }
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
            genesis
                .simplex
                .map(|parameters| std::time::Duration::from_millis(parameters.stall_timeout_ms)),
        )
        .map_err(|error| EmbedError::Config(error.reason()))?;
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
        let (term, seat) = TermControl::new();
        let mut devices = config.backups;
        if let Some(switching) = &config.switching {
            devices.extend(switching.devices.iter().map(|device| device.key.clone()));
        }
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
                            Err(match result {
                                Ok(()) => EmbedError::Stopped("node actors exited".into()),
                                Err(error) => match error.downcast::<TermRefusal>() {
                                    Ok(refusal) => EmbedError::Term(refusal),
                                    Err(error) => EmbedError::Stopped(format!("{error:#}")),
                                },
                            })
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
            identity,
            backup: is_backup,
            data_dir,
            deployment,
            config: configured,
            term,
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

    /// The key the account's other devices know this node by: the validator
    /// key on the active device, the device's transport key on a backup.
    #[must_use]
    pub const fn identity(&self) -> &PublicKey {
        &self.identity
    }

    /// The deployment's genesis record and current key material, as
    /// [`EmbeddedConfig::adopt`] accepts them on another device.
    ///
    /// The result lets its holder finalize blocks for the deployment. It
    /// carries no state, and nothing prevents two devices from running it at
    /// once, which forks the deployment. See `docs/embedded-node.md`.
    ///
    /// A backup holds no key material and fails with [`SoloError::Incomplete`].
    pub fn export(&self) -> Result<SoloDeployment, SoloError> {
        if self.backup {
            return Err(SoloError::Incomplete("a backup holds no key material"));
        }
        self.deployment.as_ref().map_or_else(
            || crate::solo::export_solo(&self.data_dir),
            |deployment| Ok(deployment.clone()),
        )
    }

    /// The term this device holds: the term it proposes in while it is
    /// active, and the lowest it accepts above that term's cut. A deployment
    /// whose active device never changed is in term 0.
    #[must_use]
    pub fn term(&self) -> u64 {
        self.term.term()
    }

    /// The certificate of the newest term this device holds, verified
    /// against the operator policy in its own state. `None` in term 0.
    #[must_use]
    pub fn term_certificate(&self) -> Option<TermCertificate> {
        self.term.certificate()
    }

    /// Announce that `successor`, one of [`crate::Switching::devices`],
    /// takes the deployment over, and return the term change to certify.
    ///
    /// The node holds back new proposals, waits for the blocks it proposed
    /// to finalize, and asks the successor to confirm it holds the last of
    /// them. That block is the change's cut, so the switch loses nothing. The
    /// host has the operator policy approve the change and gives the
    /// certificate to the successor, which calls [`Self::take_over`], and to
    /// this node, which follows with [`Self::follow`].
    ///
    /// From here on this device proposes nothing, also after a restart,
    /// until it follows or [`Self::resume`] undoes the announcement. A
    /// successor that is not connected, or does not hold the final block
    /// within [`crate::Switching::answer_timeout`], fails the call with
    /// [`TermRefusal::SuccessorNotCurrent`] and the device stays active.
    pub async fn hand_over(&self, successor: &PublicKey) -> Result<TermChange, EmbedError> {
        Ok(self.term.hand_over(successor.clone()).await?)
    }

    /// Undo [`Self::hand_over`] and propose again, for a handover whose
    /// certificate was never issued.
    ///
    /// Resuming after the successor received a certificate forks the
    /// deployment: only the host knows whether it did. The first block after
    /// a resume can be late by the leader timeout.
    pub async fn resume(&self) -> Result<(), EmbedError> {
        Ok(self.term.resume().await?)
    }

    /// The term change a certificate must approve for this backup to take
    /// the deployment over without a handover: the next term, this device as
    /// holder, and its newest block as the cut.
    ///
    /// Blocks the active device finalized and this device never received are
    /// above that cut and are lost to the switch. The host asks the user to
    /// confirm before it has the change approved.
    pub async fn takeover_change(&self) -> Result<TermChange, EmbedError> {
        Ok(self.term.offer().await?)
    }

    /// Become the active device in the term `certificate` starts.
    ///
    /// The backup checks the certificate against the operator policy in its
    /// own state, that it names this device, that its term is above every
    /// term the device has seen, and that the device's newest block is the
    /// cut. It then stops and starts again in place as the deployment's
    /// validator with `keys`. A refusal leaves the backup running. Clones of
    /// [`Self::rpc`] taken before the call end with it.
    ///
    /// An error after the certificate was accepted leaves the node stopped;
    /// the certificate is stored, and a start with
    /// [`EmbeddedConfig::activated`] completes the switch.
    pub async fn take_over(
        &mut self,
        keys: SoloKeys,
        certificate: TermCertificate,
    ) -> Result<(), EmbedError> {
        let config = self.config.activated(keys)?;
        self.term.accept(certificate, Accept::TakeOver).await?;
        self.restart(config).await
    }

    /// Follow the device that holds the term `certificate` starts.
    ///
    /// The node checks the certificate against the operator policy in its
    /// own state and that it names another of the account's devices. It then
    /// stops and starts again in place as a backup of that device. A refusal
    /// leaves the node running.
    ///
    /// Blocks this device finalized above the certificate's cut are void in
    /// the new term. The device drops them, takes its state again from the
    /// holder, and returns the submissions those blocks had finalized, which
    /// no other device holds; see [`Self::discarded`].
    ///
    /// An error after the certificate was accepted leaves the node stopped;
    /// a start with [`EmbeddedConfig::following`] completes the switch.
    pub async fn follow(
        &mut self,
        certificate: TermCertificate,
    ) -> Result<Vec<DiscardedSubmission>, EmbedError> {
        let switching = self
            .config
            .switching
            .as_ref()
            .ok_or(TermRefusal::NotConfigured)?;
        let holder = switching
            .devices
            .iter()
            .find(|device| device_id(&device.key) == certificate.change.holder)
            .ok_or(TermRefusal::Holder)?;
        let config = self.config.following(&holder.key)?;
        // A device told of a later term by its wake check already stored the certificate.
        if self.term.certificate().as_ref() != Some(&certificate) {
            self.term.accept(certificate, Accept::Follow).await?;
        }
        self.restart(config).await?;
        self.discarded()
    }

    /// The finalized submissions that rewinds of this device voided and the
    /// host has not acknowledged, in the order they had executed.
    ///
    /// A device that follows a later term drops the blocks it finalized
    /// above that term's cut. The report is written before they are dropped
    /// and kept in the data directory, so it survives a restart. The host
    /// submits again what it still wants, to the active device, and then
    /// calls [`Self::acknowledge_discarded`].
    pub fn discarded(&self) -> Result<Vec<DiscardedSubmission>, EmbedError> {
        Ok(crate::term::discarded(&self.data_dir)?)
    }

    /// Forget the report [`Self::discarded`] returns.
    pub fn acknowledge_discarded(&self) -> Result<(), EmbedError> {
        Ok(crate::term::acknowledge(&self.data_dir)?)
    }

    /// Resolves when this active device learns that another device holds a
    /// later term, with that term's certificate.
    ///
    /// The device asks the others after a gap in its own blocks longer than
    /// [`crate::Switching::freshness`]: after it was stopped or the machine
    /// slept. Once this resolves it proposes nothing more, and the host
    /// calls [`Self::follow`] with the certificate.
    pub async fn demoted(&self) -> TermCertificate {
        self.term.demoted().await
    }

    /// Stop this node and start one with `config` in its place.
    async fn restart(&mut self, config: EmbeddedConfig) -> Result<(), EmbedError> {
        self.halt().await?;
        *self = Self::start(config).await?;
        Ok(())
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
        self.halt().await
    }

    async fn halt(&mut self) -> Result<(), EmbedError> {
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

/// Refuse a role the device's stored term rules out.
///
/// A device that announced a handover, or that knows another device holds
/// the newest term, must not validate: it would finalize blocks beside the
/// device that replaced it.
fn refuse_role(config: &EmbeddedConfig) -> Result<(), EmbedError> {
    if matches!(config.role, DeviceRole::Backup(_)) {
        return Ok(());
    }
    if config.switching.is_some() && config.deployment.is_none() {
        return Err(TermRefusal::KeysInFiles.into());
    }
    let record = TermRecord::load(&config.data_dir)?;
    if let Some(change) = record.handed_over {
        return Err(TermRefusal::HandedOver(Box::new(change)).into());
    }
    let Some(certificate) = record.deciding().cloned() else {
        return Ok(());
    };
    let this = config
        .switching
        .as_ref()
        .map(|switching| device_id(&switching.device_key.public_key()));
    if this != Some(certificate.change.holder) {
        return Err(TermRefusal::Superseded(Box::new(certificate)).into());
    }
    Ok(())
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
