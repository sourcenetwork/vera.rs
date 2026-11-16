//! The node's side of a switch: it answers the host and the other devices.

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use alloy_primitives::B256;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Supervisor as _, tokio::Context};
use vera_domain::{PublicKey, TermCertificate, TermChange, TermCut};
use vera_executor::SharedModuleState;
use vera_indexer::BlockIndex;
use vera_jsonrpc::NodeState;

use super::{
    Accept, Switching, TermRecord, TermRefusal, TermSeat,
    control::{Command, View},
    device_id,
    probe::Probe,
    wire::{Message, Status},
};
use crate::ProposalHold;

/// Longest a handover waits for the blocks already proposed to finalize.
const SETTLE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(100);

/// Whether the consensus archive holds a finalized block at a height.
/// Execution may not have reached it yet.
pub(crate) type Finalized =
    Arc<dyn Fn(u64) -> futures::future::BoxFuture<'static, bool> + Send + Sync>;

/// What the term actor works with.
pub(crate) struct Parts<S, R> {
    pub seat: TermSeat,
    pub record: TermRecord,
    pub data_dir: PathBuf,
    pub switching: Option<Switching>,
    /// Whether this node follows the deployment instead of validating it.
    pub backup: bool,
    pub genesis_id: B256,
    pub hold: ProposalHold,
    pub index: Arc<BlockIndex>,
    pub finalized: Finalized,
    pub modules: SharedModuleState,
    pub status: NodeState,
    pub network: (S, R),
    /// What a wake check dials the other devices with.
    pub probe: Option<Probe>,
}

struct Actor<S, R> {
    context: Context,
    view: Arc<View>,
    record: TermRecord,
    data_dir: PathBuf,
    switching: Option<Switching>,
    backup: bool,
    genesis_id: B256,
    hold: ProposalHold,
    index: Arc<BlockIndex>,
    finalized: Finalized,
    modules: SharedModuleState,
    status: NodeState,
    sender: S,
    receiver: R,
    probe: Option<Probe>,
    /// The newest answer of each device.
    heard: HashMap<PublicKey, Status>,
}

/// Answer the host and the other devices until the node stops.
pub(crate) async fn run<S, R>(context: Context, parts: Parts<S, R>)
where
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    let TermSeat {
        mut commands, view, ..
    } = parts.seat;
    let mut actor = Actor {
        context,
        view,
        record: parts.record,
        data_dir: parts.data_dir,
        switching: parts.switching,
        backup: parts.backup,
        genesis_id: parts.genesis_id,
        hold: parts.hold,
        index: parts.index,
        finalized: parts.finalized,
        modules: parts.modules,
        status: parts.status,
        sender: parts.network.0,
        receiver: parts.network.1,
        probe: parts.probe,
        heard: HashMap::new(),
    };
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(command) => actor.handle(command).await,
                None => return,
            },
            message = actor.receiver.recv() => match message {
                Ok((peer, bytes)) => actor.hear(peer, bytes.as_ref()),
                Err(_) => return,
            },
        }
    }
}

impl<S, R> Actor<S, R>
where
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    async fn handle(&mut self, command: Command) {
        match command {
            Command::HandOver { successor, reply } => {
                let _ = reply.send(self.hand_over(successor).await);
            }
            Command::Resume { reply } => {
                let _ = reply.send(self.resume());
            }
            Command::Offer { reply } => {
                let _ = reply.send(self.offer().await);
            }
            Command::Accept {
                certificate,
                role,
                reply,
            } => {
                let _ = reply.send(self.accept(*certificate, role).await);
            }
            Command::Probe { reply } => {
                let _ = reply.send(self.probe().await);
            }
        }
    }

    fn hear(&mut self, peer: PublicKey, bytes: &[u8]) {
        match Message::decode(bytes) {
            Some(Message::Query) => {
                let status = Message::Status(self.standing());
                let _ = self
                    .sender
                    .send(Recipients::One(peer), status.encode(), true);
            }
            Some(Message::Status(status)) => {
                self.heard.insert(peer, status);
            }
            None => {}
        }
    }

    /// The newest finalized block this node serves.
    fn head(&self) -> TermCut {
        self.index.latest_block().map_or(
            TermCut {
                height: 0,
                block: self.genesis_id,
            },
            |block| TermCut {
                height: block.number,
                block: block.hash,
            },
        )
    }

    fn standing(&self) -> Status {
        let head = self.head();
        Status {
            height: head.height,
            block: head.block,
            certificate: self.record.certificate.clone(),
        }
    }

    /// The newest term this node holds or has seen in a finalized block.
    fn seen(&self) -> u64 {
        let guard = &self.view.guard;
        guard.term().max(guard.tip().map_or(0, |(_, term)| term))
    }

    fn switching(&self) -> Result<&Switching, TermRefusal> {
        self.switching.as_ref().ok_or(TermRefusal::NotConfigured)
    }

    fn this_device(&self) -> Result<B256, TermRefusal> {
        Ok(device_id(&self.switching()?.device_key.public_key()))
    }

    async fn hand_over(&mut self, successor: PublicKey) -> Result<TermChange, TermRefusal> {
        let switching = self.switching()?;
        if self.backup {
            return Err(TermRefusal::Backup);
        }
        if switching.device(&successor).is_none() {
            return Err(TermRefusal::UnknownDevice(Box::new(successor)));
        }
        let wait = switching.answer_timeout;
        if !self.hold.settle(SETTLE).await {
            self.hold.release();
            return Err(TermRefusal::Unsettled);
        }
        let cut = self.head();
        if !self.confirmed(&successor, &cut, wait).await {
            self.hold.release();
            return Err(TermRefusal::SuccessorNotCurrent { height: cut.height });
        }
        let change = TermChange {
            genesis_id: self.genesis_id,
            term: self.seen() + 1,
            holder: device_id(&successor),
            cut,
        };
        let mut record = self.record.clone();
        record.handed_over = Some(change);
        if let Err(error) = record.store(&self.data_dir) {
            self.hold.release();
            return Err(error);
        }
        self.record = record;
        Ok(change)
    }

    /// Whether `device` reports `cut` as its newest block before `wait` runs out.
    async fn confirmed(&mut self, device: &PublicKey, cut: &TermCut, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        self.heard.remove(device);
        loop {
            let _ = self.sender.send(
                Recipients::One(device.clone()),
                Message::Query.encode(),
                true,
            );
            if let Ok(Ok((peer, bytes))) = tokio::time::timeout(POLL, self.receiver.recv()).await {
                self.hear(peer, bytes.as_ref());
            }
            if self
                .heard
                .get(device)
                .is_some_and(|status| status.height == cut.height && status.block == cut.block)
            {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
        }
    }

    fn resume(&mut self) -> Result<(), TermRefusal> {
        if self.backup {
            return Err(TermRefusal::Backup);
        }
        if self.view.demoted.borrow().is_some() {
            let certificate = self.record.certificate.clone();
            return Err(certificate.map_or(TermRefusal::Stopped, |certificate| {
                TermRefusal::Superseded(Box::new(certificate))
            }));
        }
        let mut record = self.record.clone();
        record.handed_over = None;
        record.store(&self.data_dir)?;
        self.record = record;
        self.hold.release();
        Ok(())
    }

    async fn offer(&self) -> Result<TermChange, TermRefusal> {
        let holder = self.this_device()?;
        if !self.backup {
            return Err(TermRefusal::Active);
        }
        let cut = self.executed(self.switching()?.answer_timeout).await?;
        Ok(TermChange {
            genesis_id: self.genesis_id,
            term: self.seen() + 1,
            holder,
            cut,
        })
    }

    /// The newest block, once execution has reached every finalized block
    /// the consensus archive holds. A cut chosen below such a block would
    /// void a block this device is about to apply.
    ///
    /// A finalization whose block never arrived does not count: the block is
    /// lost with the device that built it.
    async fn executed(&self, wait: Duration) -> Result<TermCut, TermRefusal> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let head = self.head();
            if !(self.finalized)(head.height + 1).await {
                return Ok(head);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(TermRefusal::NotAtCut {
                    head: head.height + 1,
                    cut: head.height,
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }

    fn verify(&self, certificate: &TermCertificate) -> Result<(), TermRefusal> {
        let policy = self
            .modules
            .read()
            .map_err(|_| TermRefusal::Policy("module state lock poisoned".into()))?
            .vera
            .administration()
            .map_err(|error| TermRefusal::Policy(error.to_string()))?
            .ok_or_else(|| TermRefusal::Policy("operator authority is not configured".into()))?
            .policy;
        certificate.verify(
            &self.genesis_id,
            policy.threshold,
            policy.keys.len(),
            |signer, digest, signature| policy.verifies(signer, digest, signature),
        )?;
        Ok(())
    }

    async fn accept(
        &mut self,
        certificate: TermCertificate,
        role: Accept,
    ) -> Result<(), TermRefusal> {
        let this = self.this_device()?;
        let wait = self.switching()?.answer_timeout;
        self.verify(&certificate)?;
        let change = certificate.change;
        match role {
            Accept::TakeOver => {
                if !self.backup {
                    return Err(TermRefusal::Active);
                }
                if change.holder != this {
                    return Err(TermRefusal::Holder);
                }
                let held = self.seen();
                if change.term <= held {
                    return Err(TermRefusal::Stale {
                        offered: change.term,
                        held,
                    });
                }
                self.reach(&change.cut, wait).await?;
                let mut record = self.record.clone();
                record.taking_over = Some(certificate);
                record.store(&self.data_dir)?;
                self.record = record;
                return Ok(());
            }
            Accept::Follow => {
                if change.holder == this {
                    return Err(TermRefusal::Holder);
                }
                let held = self.record.change().map_or(0, |held| held.term);
                if change.term <= held {
                    return Err(TermRefusal::Stale {
                        offered: change.term,
                        held,
                    });
                }
                self.hold.hold();
            }
        }
        self.store(certificate)
    }

    /// Wait until this node's newest block is `cut`. The final block of a
    /// handover may still be on its way.
    async fn reach(&self, cut: &TermCut, wait: Duration) -> Result<(), TermRefusal> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let head = self.head();
            let above = (self.finalized)(cut.height + 1).await;
            if head == *cut && !above {
                return Ok(());
            }
            if above || head.height >= cut.height || tokio::time::Instant::now() >= deadline {
                return Err(TermRefusal::NotAtCut {
                    head: head.height.max(cut.height + u64::from(above)),
                    cut: cut.height,
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Keep a verified certificate of another device's term. The node
    /// refuses the blocks it voids from its next start on.
    fn store(&mut self, certificate: TermCertificate) -> Result<(), TermRefusal> {
        let record = TermRecord {
            certificate: Some(certificate.clone()),
            handed_over: None,
            taking_over: None,
            voted: self.record.voted,
            resync: self.record.resync,
        };
        record.store(&self.data_dir)?;
        self.record = record;
        *self.view.certificate.write() = Some(certificate.clone());
        self.status.set_term_certificate(certificate);
        Ok(())
    }

    /// Ask every other device for a later term. Returns whether this device
    /// may still propose.
    async fn probe(&mut self) -> bool {
        let (Some(switching), Some(probe), false) = (&self.switching, &self.probe, self.backup)
        else {
            return true;
        };
        let this = device_id(&switching.device_key.public_key());
        let asked = switching
            .devices
            .iter()
            .map(|device| probe.ask(self.context.child("term_probe"), device.address));
        let held = self.seen();
        let later = futures::future::join_all(asked)
            .await
            .into_iter()
            .flatten()
            .filter_map(|status| status.certificate)
            .filter(|certificate| {
                let change = &certificate.change;
                change.term > held && change.holder != this && self.verify(certificate).is_ok()
            })
            .max_by_key(|certificate| certificate.change.term);
        let Some(certificate) = later else {
            return true;
        };
        tracing::warn!(
            term = certificate.change.term,
            cut = certificate.change.cut.height,
            "another device holds a later term; this device stops proposing"
        );
        self.hold.hold();
        self.view
            .guard
            .raise(certificate.change.term, certificate.change.cut.height);
        if let Err(error) = self.store(certificate.clone()) {
            tracing::error!(%error, "term certificate could not be stored");
        }
        self.view.demoted.send_replace(Some(certificate));
        false
    }
}
