//! Settings for a node hosted inside another program.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use vera_config::{DiscoveryConfig, NetworkConfig, NodeConfig, PruningConfig, SnapshotConfig};
use vera_domain::PublicKey;

use super::{Backup, DeviceRole, ThreadBudget, ThreadSetup};
use crate::{
    HistoryMemory, NodeSizing, SoloDeployment, SoloError, SoloGenesis, SoloKeys, SoloPacing,
    Switching, TermRefusal,
};

/// Configuration of an embedded single-validator node.
#[derive(Clone, Debug)]
pub struct EmbeddedConfig {
    /// Directory owned by this node. It must not be shared with another store.
    pub data_dir: PathBuf,
    /// Deployment identity, fixed when the directory is first used.
    pub genesis: SoloGenesis,
    /// An existing deployment whose key material the host holds.
    ///
    /// The node opens it instead of creating one, signs from memory and writes
    /// neither the validator key nor the consensus share to the directory.
    /// `None` creates the deployment on first use and keeps both in files there.
    pub deployment: Option<SoloDeployment>,
    /// Whether this device validates the deployment or follows the device that does.
    pub role: DeviceRole,
    /// Transport keys of the account's backup devices.
    ///
    /// The active device accepts a connection only from a backup listed here.
    /// A backup connects to the active device alone and ignores the list. It
    /// is configuration: nothing in the deployment's state records it.
    pub backups: Vec<PublicKey>,
    /// The account's devices, for a deployment whose active device may
    /// change. `None` runs the role the configuration states for good.
    ///
    /// With it, the active device also admits every listed device as a
    /// backup, and a backup's transport key is the one given here.
    pub switching: Option<Switching>,
    /// Finality stall, in whole seconds, after which the node stops with an error.
    /// Less than a second never stops it.
    ///
    /// A validator counts a stall whenever it could finalize; a backup only
    /// while it is connected to the active device.
    pub watchdog_stall: Duration,
    /// Longest a backup started on an empty directory waits for the active
    /// device to answer, and then for its state to arrive, before the start fails.
    pub catch_up_timeout: Duration,
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
    /// Default interval between the empty blocks an idle deployment finalizes.
    ///
    /// A client that verifies state against finalized headers refuses a state
    /// older than its freshness limit, 30 seconds in Backbone's light client,
    /// so an idle deployment cannot stop finalizing altogether.
    pub const HEARTBEAT: Duration = Duration::from_secs(10);

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
            deployment: None,
            role: DeviceRole::Active,
            backups: Vec::new(),
            switching: None,
            watchdog_stall: Duration::from_secs(NodeConfig::default().watchdog_stall_seconds),
            catch_up_timeout: Duration::from_millis(
                SnapshotConfig::default().initialization_timeout_ms,
            ),
            p2p_listen,
            rpc_listen: None,
            leader_timeout: Duration::from_secs(12),
            certification_timeout: Duration::from_secs(13),
            timeout_retry: Duration::from_millis(500),
            pruning: Some(Self::RETENTION),
            pacing: Some(SoloPacing {
                idle: Self::HEARTBEAT,
                batch: SoloPacing::BATCH,
            }),
            worker_threads: None,
            max_blocking_threads: None,
            verification_threads: crate::options::default_verification_threads().get(),
            thread_setup: None,
            history_memory: HistoryMemory::EMBEDDED,
            sizing: NodeSizing::EMBEDDED,
        }
    }

    /// Defaults for a node that opens `deployment`, in an empty directory or
    /// in one that already holds it.
    ///
    /// The identity to check the directory against is read from the record.
    pub fn adopt(
        data_dir: impl Into<PathBuf>,
        deployment: SoloDeployment,
        p2p_listen: SocketAddr,
    ) -> Result<Self, SoloError> {
        let mut config = Self::new(data_dir, deployment.identity()?, p2p_listen);
        config.deployment = Some(deployment);
        Ok(config)
    }

    /// Defaults for a backup of the deployment `record` describes, following
    /// the active device that listens at `active`.
    ///
    /// The directory may be empty, or hold this deployment from an earlier run
    /// as a backup. The device's transport key is kept in the directory unless
    /// [`Backup::transport_key`] supplies it.
    pub fn backup(
        data_dir: impl Into<PathBuf>,
        record: impl Into<Vec<u8>>,
        p2p_listen: SocketAddr,
        active: SocketAddr,
    ) -> Result<Self, SoloError> {
        let record = record.into();
        let mut config = Self::new(data_dir, crate::solo::record_identity(&record)?, p2p_listen);
        config.role = DeviceRole::Backup(Box::new(Backup {
            record,
            active,
            transport_key: None,
        }));
        Ok(config)
    }

    /// This configuration for the same device as the deployment's validator,
    /// with the key material `keys`. The device was configured as a backup,
    /// or as the active device that renews its term.
    ///
    /// [`crate::EmbeddedNode::take_over`] starts a node with it once a term
    /// certificate names the device. A host uses it directly to start a
    /// device that already took the deployment over.
    pub fn activated(&self, keys: SoloKeys) -> Result<Self, TermRefusal> {
        let record = match (&self.role, &self.deployment) {
            (DeviceRole::Backup(backup), _) => backup.record.clone(),
            (DeviceRole::Active, Some(deployment)) => deployment.record().to_vec(),
            (DeviceRole::Active, None) => return Err(TermRefusal::KeysInFiles),
        };
        let mut config = self.clone();
        config.deployment = Some(SoloDeployment::new(record, keys));
        config.role = DeviceRole::Active;
        Ok(config)
    }

    /// This configuration for the same device as a backup of the device
    /// `holder`, one of [`Switching::devices`].
    ///
    /// [`crate::EmbeddedNode::follow`] starts a node with it. A host uses it
    /// directly to start a device that handed the deployment over, or that
    /// another device replaced.
    pub fn following(&self, holder: &PublicKey) -> Result<Self, TermRefusal> {
        let switching = self.switching.as_ref().ok_or(TermRefusal::NotConfigured)?;
        let device = switching
            .device(holder)
            .ok_or_else(|| TermRefusal::UnknownDevice(Box::new(holder.clone())))?;
        let record = match (&self.role, &self.deployment) {
            (DeviceRole::Backup(backup), _) => backup.record.clone(),
            (DeviceRole::Active, Some(deployment)) => deployment.record().to_vec(),
            (DeviceRole::Active, None) => return Err(TermRefusal::KeysInFiles),
        };
        let mut config = self.clone();
        config.deployment = None;
        config.role = DeviceRole::Backup(Box::new(Backup {
            record,
            active: device.address,
            transport_key: Some(switching.device_key.clone()),
        }));
        Ok(config)
    }

    /// The daemon configuration of this node. Its listener may sit on
    /// loopback, so it states the local discovery settings.
    pub(super) fn node_config(&self) -> NodeConfig {
        NodeConfig {
            chain_id: self.genesis.chain_id,
            data_dir: self.data_dir.clone(),
            network: NetworkConfig {
                listen_addr: self.p2p_listen.to_string(),
                discovery: DiscoveryConfig::local(),
                ..NetworkConfig::default()
            },
            pruning: self.pruning.clone(),
            // A backup starts from the active device's state, not from genesis.
            snapshot: matches!(self.role, DeviceRole::Backup(_)).then(|| SnapshotConfig {
                initialization_timeout_ms: self
                    .catch_up_timeout
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                ..SnapshotConfig::default()
            }),
            watchdog_stall_seconds: self.watchdog_stall.as_secs(),
            ..NodeConfig::default()
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

#[cfg(test)]
mod tests {
    use vera_modules::vera::administration::OperatorPolicy;

    use super::*;

    #[test]
    fn the_node_configuration_states_the_local_discovery_settings() {
        let genesis = SoloGenesis {
            chain_id: 9_271,
            operators: OperatorPolicy {
                threshold: 1,
                keys: vec![
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
                ],
            },
            timestamp: 1_800_000_000,
            policies: Vec::new(),
        };
        let listen = "127.0.0.1:0".parse().unwrap();
        let config = EmbeddedConfig::new("/tmp/embedded", genesis, listen).node_config();
        assert_eq!(config.chain_id, 9_271);
        assert_eq!(config.network.listen_addr, "127.0.0.1:0");
        assert_eq!(config.network.discovery, DiscoveryConfig::local());
        assert_eq!(config.pruning, Some(EmbeddedConfig::RETENTION));
    }
}
