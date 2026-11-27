//! A validator hosted inside another program.
//!
//! The node runs on its own thread and Commonware runtime, so the host needs no
//! particular async runtime. Stopping drops that runtime; durability relies on
//! the same recovery path as an interrupted daemon.

mod config;
mod directory;
mod error;
mod launch;
mod role;
mod rpc_socket;
mod thread;
mod thread_budget;
mod thread_setup;

use std::net::SocketAddr;

use launch::Launched;
use vera_domain::{ConsensusPublicKey, PublicKey, TermCertificate, TermChange};
use vera_genesis::VeraGenesis;
use vera_jsonrpc::LocalRpc;

pub use config::EmbeddedConfig;
pub use error::EmbedError;
pub use role::{Backup, DeviceRole};
use rpc_socket::RpcSocket;
pub use thread_budget::ThreadBudget;
pub use thread_setup::ThreadSetup;

use crate::{
    DiscardedSubmission, SoloDeployment, SoloError, SoloKeys, TermRefusal,
    term::{Accept, TermRecord, device_id},
};

/// A running embedded node.
#[derive(Debug)]
pub struct EmbeddedNode {
    rpc: LocalRpc,
    node: Launched,
    /// Set while a switch runs, and left set by one that failed or was dropped.
    interrupted: bool,
}

impl EmbeddedNode {
    /// Create or reopen the deployment and return once the node serves requests.
    ///
    /// Dropping the call before it returns leaves a node that stops by
    /// itself; until it has, the directory is in use.
    pub async fn start(config: EmbeddedConfig) -> Result<Self, EmbedError> {
        let (mut node, mut ready) = launch::launch(config, None)?;
        let rpc = node.thread.started(&mut ready).await?;
        Ok(Self {
            rpc,
            node,
            interrupted: false,
        })
    }

    /// The node's methods, callable without a socket.
    #[must_use]
    pub const fn rpc(&self) -> &LocalRpc {
        &self.rpc
    }

    /// The address the network RPC listener is bound to, with the port the
    /// system chose when [`EmbeddedConfig::rpc_listen`] asked for port 0.
    /// `None` when the node has no network listener.
    #[must_use]
    pub fn rpc_addr(&self) -> Option<SocketAddr> {
        self.node.rpc_socket.as_ref().map(RpcSocket::address)
    }

    /// The deployment's genesis.
    #[must_use]
    pub const fn genesis(&self) -> &VeraGenesis {
        &self.node.genesis
    }

    /// The consensus key that finality proofs from this deployment verify against.
    #[must_use]
    pub const fn consensus_key(&self) -> &ConsensusPublicKey {
        &self.node.consensus_key
    }

    /// The key the account's other devices know this node by: the validator
    /// key on the active device, the device's transport key on a backup.
    #[must_use]
    pub const fn identity(&self) -> &PublicKey {
        &self.node.identity
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
        if self.node.backup {
            return Err(SoloError::Incomplete("a backup holds no key material"));
        }
        self.node.deployment.as_ref().map_or_else(
            || crate::solo::export_solo(&self.node.data_dir),
            |deployment| Ok(deployment.clone()),
        )
    }

    /// Undo a handover that a node announced in `config`'s directory before
    /// it stopped, so the device can start as the active device again.
    ///
    /// For a handover whose certificate was never issued: the host quit
    /// before the operators approved. As with [`Self::resume`], resuming
    /// after the successor received a certificate forks the deployment. A
    /// device that knows another device holds a later term is refused with
    /// [`TermRefusal::Superseded`].
    pub fn resume_stopped(config: &EmbeddedConfig) -> Result<(), EmbedError> {
        let _claim = directory::claim(&config.data_dir)?;
        let storage = config.data_dir.join("commonware");
        if storage.is_dir() {
            directory::refuse_held(&storage)?;
        }
        let this = config
            .switching
            .as_ref()
            .map(|switching| device_id(&switching.device_key.public_key()))
            .ok_or(TermRefusal::NotConfigured)?;
        let mut record = TermRecord::load(&config.data_dir)?;
        if let Some(certificate) = record.deciding()
            && certificate.change.holder != this
        {
            return Err(TermRefusal::Superseded(Box::new(certificate.clone())).into());
        }
        // The device is still the holder of its term, also if it started to
        // follow the successor meanwhile. If the successor did take over, the
        // start as validator is refused on the later term of its blocks.
        record.handed_over = None;
        record.followed = false;
        Ok(record.store(&config.data_dir)?)
    }

    /// The term this device holds: the term it proposes in while it is
    /// active, and the lowest it accepts above that term's cut. A deployment
    /// whose active device never changed is in term 0.
    #[must_use]
    pub fn term(&self) -> u64 {
        self.node.term.term()
    }

    /// The certificate of the newest term this device holds, verified
    /// against the operator policy in its own state. `None` in term 0.
    #[must_use]
    pub fn term_certificate(&self) -> Option<TermCertificate> {
        self.node.term.certificate()
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
        self.running()?;
        Ok(self.node.term.hand_over(successor.clone()).await?)
    }

    /// Undo [`Self::hand_over`] and propose again, for a handover whose
    /// certificate was never issued.
    ///
    /// Resuming after the successor received a certificate forks the
    /// deployment: only the host knows whether it did. The first block after
    /// a resume can be late by the leader timeout.
    pub async fn resume(&self) -> Result<(), EmbedError> {
        self.running()?;
        Ok(self.node.term.resume().await?)
    }

    /// The term change a certificate must approve for this backup to take
    /// the deployment over without a handover: the next term, this device as
    /// holder, and its newest block as the cut.
    ///
    /// Blocks the active device finalized and this device never received are
    /// above that cut and are lost to the switch. The host asks the user to
    /// confirm before it has the change approved.
    pub async fn takeover_change(&self) -> Result<TermChange, EmbedError> {
        self.running()?;
        Ok(self.node.term.offer().await?)
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
    ///
    /// The call may be dropped. Dropped before the certificate was accepted,
    /// the backup keeps running and the call is repeated. Dropped after, the
    /// node is stopped or stopping as after an error: further calls on it
    /// fail with [`EmbedError::Interrupted`], and [`Self::stop`] joins it.
    pub async fn take_over(
        &mut self,
        keys: SoloKeys,
        certificate: TermCertificate,
    ) -> Result<(), EmbedError> {
        self.running()?;
        let config = self.node.config.activated(keys)?;
        self.node.term.accept(certificate, Accept::TakeOver).await?;
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
    /// Dropping the call does what dropping [`Self::take_over`] does.
    pub async fn follow(
        &mut self,
        certificate: TermCertificate,
    ) -> Result<Vec<DiscardedSubmission>, EmbedError> {
        self.running()?;
        let switching = self
            .node
            .config
            .switching
            .as_ref()
            .ok_or(TermRefusal::NotConfigured)?;
        let holder = switching
            .devices
            .iter()
            .find(|device| device_id(&device.key) == certificate.change.holder)
            .ok_or(TermRefusal::Holder)?;
        let config = self.node.config.following(&holder.key)?;
        self.node.term.accept(certificate, Accept::Follow).await?;
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
        Ok(crate::term::discarded(&self.node.data_dir)?)
    }

    /// Forget the report [`Self::discarded`] returns.
    pub fn acknowledge_discarded(&self) -> Result<(), EmbedError> {
        Ok(crate::term::acknowledge(&self.node.data_dir)?)
    }

    /// Resolves when this active device learns that another device holds a
    /// later term, with that term's certificate.
    ///
    /// The device asks the others after a gap in its own blocks longer than
    /// [`crate::Switching::freshness`]: after it was stopped or the machine
    /// slept. Once this resolves it proposes nothing more, and the host
    /// calls [`Self::follow`] with the certificate.
    pub async fn demoted(&self) -> TermCertificate {
        self.node.term.demoted().await
    }

    /// Resolves when another device answers this active device as the
    /// deployment's validator and no certificate settles which of them holds
    /// the term.
    ///
    /// This device proposes nothing while the other keeps answering, and
    /// asks again at each of its turns. Nothing is stored. The host follows
    /// with a certificate this device can verify, or stops the other device.
    pub async fn contested(&self) -> crate::Contest {
        self.node.term.contested().await
    }

    /// Stop this node and start one with `config` in its place.
    ///
    /// The node owns the thread it stops and the thread it starts before it
    /// waits for either, so a caller dropped during a wait leaves both to
    /// [`Self::stop`].
    async fn restart(&mut self, config: EmbeddedConfig) -> Result<(), EmbedError> {
        self.interrupted = true;
        let switch = Switch(self);
        switch.0.node.thread.halt().await?;
        let rpc_socket = switch.0.node.rpc_socket.take();
        let (node, mut ready) = launch::launch(config, rpc_socket)?;
        switch.0.node = node;
        switch.0.rpc = switch.0.node.thread.started(&mut ready).await?;
        switch.0.interrupted = false;
        Ok(())
    }

    /// Refuse a call on a node that a switch stopped and did not start again.
    const fn running(&self) -> Result<(), EmbedError> {
        if self.interrupted {
            return Err(EmbedError::Interrupted);
        }
        Ok(())
    }

    /// Wait until the node stops on its own, which is always an error.
    ///
    /// After a switch that failed or was dropped midway this resolves at
    /// once with [`EmbedError::Interrupted`].
    pub async fn failed(&mut self) -> EmbedError {
        if self.interrupted {
            return EmbedError::Interrupted;
        }
        self.node.thread.failed().await
    }

    /// Stop the node and wait for its thread to finish.
    ///
    /// When this returns, with `Ok` or with the error the node ended on, no
    /// thread of the node runs and its directory is free. That holds after a
    /// [`Self::take_over`] or [`Self::follow`] that failed or was dropped
    /// midway: this waits for the thread that call was stopping or had
    /// started. Dropping this call before it returns leaves the thread to
    /// stop by itself, like dropping the node.
    pub async fn stop(mut self) -> Result<(), EmbedError> {
        self.node.thread.halt().await
    }
}

/// A switch in progress. One that ends before the new node serves leaves the
/// node marked as interrupted and its thread told to stop.
struct Switch<'a>(&'a mut EmbeddedNode);

impl Drop for Switch<'_> {
    fn drop(&mut self) {
        if self.0.interrupted {
            self.0.node.thread.signal();
        }
    }
}

/// Refuse a role the device's stored term rules out.
///
/// A device that announced a handover, that knows another device holds the
/// newest term, or that followed the deployment and has accepted no
/// certificate naming it since, must not validate: it would finalize blocks
/// beside the active device. A certificate naming this device that it held
/// before it followed does not count; resuming (`resume_stopped`) does.
fn refuse_role(config: &EmbeddedConfig) -> Result<(), EmbedError> {
    if matches!(config.role, DeviceRole::Backup(_)) {
        return Ok(());
    }
    if config.switching.is_some() && config.deployment.is_none() {
        return Err(TermRefusal::KeysInFiles.into());
    }
    if let Some(switching) = &config.switching
        && config.leader_timeout <= switching.answer_timeout
    {
        return Err(EmbedError::Config(
            "the answer timeout must be shorter than the leader timeout",
        ));
    }
    let record = TermRecord::load(&config.data_dir)?;
    let this = config
        .switching
        .as_ref()
        .map(|switching| device_id(&switching.device_key.public_key()));
    let named = |certificate: &TermCertificate| this == Some(certificate.change.holder);
    // A takeover this device accepted is later than a handover it announced.
    if record.taking_over.as_ref().is_some_and(named) {
        return Ok(());
    }
    if let Some(change) = record.handed_over {
        return Err(TermRefusal::HandedOver(Box::new(change)).into());
    }
    match record.deciding() {
        Some(certificate) if !named(certificate) => {
            Err(TermRefusal::Superseded(Box::new(certificate.clone())).into())
        }
        _ if record.followed => Err(TermRefusal::NotCertified.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod cancel_tests;

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use vera_domain::{TermChange, TermCut};
    use vera_modules::vera::administration::OperatorPolicy;

    use super::*;
    use crate::{DeviceKey, SoloGenesis, Switching};

    fn switching(directory: &std::path::Path) -> (EmbeddedConfig, B256) {
        let genesis = SoloGenesis {
            chain_id: 9_272,
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
        let deployment = SoloDeployment::create(&genesis, listen).unwrap();
        let mut config = EmbeddedConfig::adopt(directory, deployment, listen).unwrap();
        let key = DeviceKey::generate().unwrap();
        let this = device_id(&key.public_key());
        config.switching = Some(Switching::new(key, Vec::new()));
        (config, this)
    }

    fn certificate(term: u64, holder: B256) -> TermCertificate {
        TermCertificate {
            change: TermChange {
                genesis_id: B256::repeat_byte(1),
                term,
                holder,
                cut: TermCut {
                    height: 10 * term,
                    block: B256::repeat_byte(3),
                },
            },
            approvals: Vec::new(),
        }
    }

    #[test]
    fn a_takeover_this_device_accepted_outlives_the_handover_it_announced() {
        let directory = tempfile::tempdir().unwrap();
        let (config, this) = switching(directory.path());
        let handed = certificate(1, B256::repeat_byte(8)).change;
        let mut record = TermRecord {
            handed_over: Some(handed),
            ..TermRecord::default()
        };
        record.store(directory.path()).unwrap();
        assert!(matches!(
            refuse_role(&config),
            Err(EmbedError::Term(TermRefusal::HandedOver(_)))
        ));
        record.taking_over = Some(certificate(2, this));
        record.store(directory.path()).unwrap();
        refuse_role(&config).unwrap();
        record.taking_over = Some(certificate(2, B256::repeat_byte(8)));
        record.store(directory.path()).unwrap();
        assert!(matches!(
            refuse_role(&config),
            Err(EmbedError::Term(TermRefusal::HandedOver(_)))
        ));
    }

    #[test]
    fn a_stopped_device_resumes_a_handover_unless_it_was_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let (config, this) = switching(directory.path());
        let mut record = TermRecord {
            handed_over: Some(certificate(1, B256::repeat_byte(8)).change),
            resync: true,
            ..TermRecord::default()
        };
        record.store(directory.path()).unwrap();
        EmbeddedNode::resume_stopped(&config).unwrap();
        refuse_role(&config).unwrap();
        assert!(TermRecord::load(directory.path()).unwrap().resync);
        record.followed = true;
        record.store(directory.path()).unwrap();
        EmbeddedNode::resume_stopped(&config).unwrap();
        refuse_role(&config).unwrap();
        record.followed = false;

        record.certificate = Some(certificate(1, B256::repeat_byte(8)));
        record.store(directory.path()).unwrap();
        assert!(matches!(
            EmbeddedNode::resume_stopped(&config),
            Err(EmbedError::Term(TermRefusal::Superseded(_)))
        ));
        record.certificate = Some(certificate(1, this));
        record.store(directory.path()).unwrap();
        EmbeddedNode::resume_stopped(&config).unwrap();
        refuse_role(&config).unwrap();
    }

    #[test]
    fn a_backup_directory_does_not_start_as_the_validator_without_a_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let (config, this) = switching(directory.path());
        refuse_role(&config).unwrap();
        crate::term::settle_role(directory.path(), false).unwrap();
        refuse_role(&config).unwrap();
        crate::term::settle_role(directory.path(), true).unwrap();
        assert!(matches!(
            refuse_role(&config),
            Err(EmbedError::Term(TermRefusal::NotCertified))
        ));
        // Starting as the validator does not by itself make the device one.
        crate::term::settle_role(directory.path(), false).unwrap();
        assert!(matches!(
            refuse_role(&config),
            Err(EmbedError::Term(TermRefusal::NotCertified))
        ));
        let mut record = TermRecord::load(directory.path()).unwrap();
        record.taking_over = Some(certificate(1, this));
        record.store(directory.path()).unwrap();
        refuse_role(&config).unwrap();
    }

    #[test]
    fn a_holder_that_followed_validates_again_only_by_resuming() {
        let directory = tempfile::tempdir().unwrap();
        let (config, this) = switching(directory.path());
        TermRecord {
            certificate: Some(certificate(1, this)),
            ..TermRecord::default()
        }
        .store(directory.path())
        .unwrap();
        refuse_role(&config).unwrap();
        crate::term::settle_role(directory.path(), true).unwrap();
        assert!(matches!(
            refuse_role(&config),
            Err(EmbedError::Term(TermRefusal::NotCertified))
        ));
        EmbeddedNode::resume_stopped(&config).unwrap();
        refuse_role(&config).unwrap();
    }

    #[test]
    fn the_answer_timeout_stays_below_the_leader_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let (mut config, _) = switching(directory.path());
        config.switching.as_mut().unwrap().answer_timeout = config.leader_timeout;
        assert!(matches!(refuse_role(&config), Err(EmbedError::Config(_))));
    }
}
