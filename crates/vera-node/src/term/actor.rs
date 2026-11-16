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
    control::{Asked, Command, View},
    device_id,
    probe::Probe,
    wire::{Message, Status},
};
use crate::ProposalHold;

/// Longest a handover waits for the blocks already proposed to finalize.
const SETTLE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(100);

/// What the consensus archive holds as finalized at a height. Execution may
/// not have reached it yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Archived {
    Nothing,
    /// The block, which execution is about to apply.
    Block,
    /// A finalization certificate whose block never arrived.
    Certificate,
}

/// Reads what the consensus archive holds at a height.
pub(crate) type Finalized =
    Arc<dyn Fn(u64) -> futures::future::BoxFuture<'static, Archived> + Send + Sync>;

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

    /// Why this device may not act as the active device, if it may not:
    /// another device holds a later term, or this one announced a handover.
    fn displaced(&self, this: &B256) -> Option<TermRefusal> {
        let later = self.view.demoted.borrow().clone().or_else(|| {
            self.record
                .certificate
                .clone()
                .filter(|certificate| certificate.change.holder != *this)
        });
        if let Some(certificate) = later {
            return Some(TermRefusal::Superseded(Box::new(certificate)));
        }
        self.record
            .handed_over
            .map(|change| TermRefusal::HandedOver(Box::new(change)))
    }

    async fn hand_over(&mut self, successor: PublicKey) -> Result<TermChange, TermRefusal> {
        let this = self.this_device()?;
        let switching = self.switching()?;
        if self.backup {
            return Err(TermRefusal::Backup);
        }
        if switching.device(&successor).is_none() {
            return Err(TermRefusal::UnknownDevice(Box::new(successor)));
        }
        // A device that already gave the deployment up, or was replaced,
        // has no term to hand over, and a failure below must not let it propose.
        if let Some(refusal) = self.displaced(&this) {
            return Err(refusal);
        }
        let wait = switching.answer_timeout;
        let held = self.hold.is_held();
        let change = self.announce(successor, wait).await;
        if change.is_err() && !held {
            self.hold.release();
        }
        change
    }

    async fn announce(
        &mut self,
        successor: PublicKey,
        wait: Duration,
    ) -> Result<TermChange, TermRefusal> {
        if !self.hold.settle(SETTLE).await {
            return Err(TermRefusal::Unsettled);
        }
        let cut = self.head();
        if !self.confirmed(&successor, &cut, wait).await {
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
        record.store(&self.data_dir)?;
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
        let this = self.this_device()?;
        if self.backup {
            return Err(TermRefusal::Backup);
        }
        if let Some(refusal @ TermRefusal::Superseded(_)) = self.displaced(&this) {
            return Err(refusal);
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
    async fn executed(&self, wait: Duration) -> Result<TermCut, TermRefusal> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let head = self.head();
            let above = (self.finalized)(head.height + 1).await;
            if above == Archived::Nothing {
                return Ok(head);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(not_at(&head, head.height, above));
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
                // The policy is read at the cut: a block on the way to it may have rotated the operators.
                self.verify(&certificate)?;
                let mut record = self.record.clone();
                record.taking_over = Some(certificate);
                record.store(&self.data_dir)?;
                self.record = record;
                Ok(())
            }
            Accept::Follow => {
                self.verify(&certificate)?;
                if change.holder == this {
                    return Err(TermRefusal::Holder);
                }
                // A term this device already holds a certificate of, or one
                // below a block it has seen, is not news. A backup may be
                // given the certificate of the term its newest blocks are in.
                let stored = self.record.change().map_or(0, |held| held.term);
                let seen = self.seen();
                if change.term <= stored || change.term < seen {
                    return Err(TermRefusal::Stale {
                        offered: change.term,
                        held: stored.max(seen),
                    });
                }
                self.hold.hold();
                self.store(certificate)
            }
        }
    }

    /// Wait until this node's newest block is `cut`. The final block of a
    /// handover may still be on its way.
    async fn reach(&self, cut: &TermCut, wait: Duration) -> Result<(), TermRefusal> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let head = self.head();
            let above = (self.finalized)(cut.height + 1).await;
            if head == *cut && above == Archived::Nothing {
                return Ok(());
            }
            let waiting = head.height < cut.height || above == Archived::Certificate;
            if !waiting || tokio::time::Instant::now() >= deadline {
                return Err(not_at(&head, cut.height, above));
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
            followed: self.record.followed,
        };
        record.store(&self.data_dir)?;
        self.record = record;
        *self.view.certificate.write() = Some(certificate.clone());
        self.status.set_term_certificate(certificate);
        Ok(())
    }

    /// Ask every other device where it stands.
    ///
    /// Only a device that runs as the validator answers, so any answer means
    /// this device must not propose. A certificate of a later term that
    /// verifies and is stored replaces it for good; anything else is reported
    /// to the host and asked again at the next proposal.
    async fn probe(&mut self) -> Asked {
        let (Some(switching), Some(probe), false) = (&self.switching, &self.probe, self.backup)
        else {
            return Asked::Clear;
        };
        let this = device_id(&switching.device_key.public_key());
        let asked = switching.devices.iter().map(|device| async {
            let answer = probe
                .ask(self.context.child("term_probe"), device.address)
                .await;
            answer.map(|status| (device.key.clone(), status))
        });
        let answers: Vec<_> = futures::future::join_all(asked)
            .await
            .into_iter()
            .flatten()
            .collect();
        let Some((device, status)) = answers.first().cloned() else {
            self.view.contested.send_replace(None);
            return Asked::Clear;
        };
        let held = self.seen();
        let later = answers
            .iter()
            .filter_map(|(_, status)| status.certificate.clone())
            .filter(|certificate| {
                let change = &certificate.change;
                change.term > held && change.holder != this && self.verify(certificate).is_ok()
            })
            .max_by_key(|certificate| certificate.change.term);
        if let Some(certificate) = later {
            match self.store(certificate.clone()) {
                Ok(()) => {
                    tracing::warn!(
                        term = certificate.change.term,
                        cut = certificate.change.cut.height,
                        "another device holds a later term; this device stops proposing"
                    );
                    self.hold.hold();
                    self.view
                        .guard
                        .raise(certificate.change.term, certificate.change.cut.height);
                    self.view.demoted.send_replace(Some(certificate));
                    return Asked::Replaced;
                }
                Err(error) => tracing::error!(%error, "term certificate could not be stored"),
            }
        }
        tracing::warn!(%device, height = status.height, "another device validates this deployment");
        self.view.contested.send_replace(Some(crate::Contest {
            device,
            height: status.height,
            block: status.block,
            certificate: status.certificate,
        }));
        Asked::Contested
    }
}

/// Why a device at `head` cannot start a term on the block at `cut`.
fn not_at(head: &TermCut, cut: u64, above: Archived) -> TermRefusal {
    match above {
        Archived::Certificate => TermRefusal::CertificateAboveCut { height: cut + 1 },
        Archived::Block => TermRefusal::NotAtCut {
            head: head.height.max(cut + 1),
            cut,
        },
        Archived::Nothing => TermRefusal::NotAtCut {
            head: head.height,
            cut,
        },
    }
}
