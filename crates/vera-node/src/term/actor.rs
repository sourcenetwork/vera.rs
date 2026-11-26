//! The node's side of a switch: it answers the host and the other devices.

mod ancestry;

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use alloy_primitives::B256;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Supervisor as _, tokio::Context};
use vera_domain::{PublicKey, TermCertificate, TermChange, TermCut};
use vera_executor::SharedModuleState;
use vera_indexer::BlockIndex;
use vera_jsonrpc::NodeState;

use super::{
    Accept, Switching, TermRecord, TermRefusal, TermSeat, WakeGate,
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

/// Reads the identifier of the block finalized history holds at a height
/// above genesis: `None` when it holds none there, an error when the read fails.
pub(crate) type Blocks = Arc<dyn Fn(u64) -> anyhow::Result<Option<B256>> + Send + Sync>;

/// Reads the oldest height finalized history retains: 1 until it is pruned.
/// [`Blocks`] fails for a height below it.
pub(crate) type HistoryFloor = Arc<dyn Fn() -> anyhow::Result<u64> + Send + Sync>;

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
    pub blocks: Blocks,
    pub history_floor: HistoryFloor,
    pub modules: SharedModuleState,
    pub status: NodeState,
    pub network: (S, R),
    /// What a wake check dials the other devices with.
    pub probe: Option<Probe>,
    /// The check proposals pass; a contest makes the next one ask again.
    pub gate: WakeGate,
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
    blocks: Blocks,
    history_floor: HistoryFloor,
    modules: SharedModuleState,
    status: NodeState,
    sender: S,
    receiver: R,
    probe: Option<Probe>,
    gate: WakeGate,
    /// The newest answer of each device.
    heard: HashMap<PublicKey, Status>,
    /// Whether this device holds a proposal back while it asks the others.
    /// The background check of a device that proposes does not.
    asking: bool,
    /// The device this one answered while it held back, since its own check
    /// began, that the exchange lets go on, and what that device asked with.
    yielded: Option<(PublicKey, Status)>,
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
        blocks: parts.blocks,
        history_floor: parts.history_floor,
        modules: parts.modules,
        status: parts.status,
        sender: parts.network.0,
        receiver: parts.network.1,
        probe: parts.probe,
        gate: parts.gate,
        heard: HashMap::new(),
        asking: false,
        yielded: None,
    };
    // An active device that stays awake asks again every freshness window:
    // another device may have been opened as the validator, or taken over,
    // while the two could not reach each other.
    let period = match (&actor.switching, &actor.probe, actor.backup) {
        (Some(switching), Some(_), false) => Some(switching.freshness),
        _ => None,
    };
    let mut recheck = period.map(|period| {
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval
    });
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
            _ = async {
                match &mut recheck {
                    Some(interval) => interval.tick().await,
                    None => std::future::pending().await,
                }
            } => actor.recheck().await,
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
            // A proposal consensus dropped no longer waits for this answer,
            // and asking for it would delay the next proposal's question.
            Command::Probe { reply } if reply.is_closed() => {}
            Command::Probe { reply } => {
                let _ = reply.send(self.probe(true).await);
            }
        }
    }

    fn hear(&mut self, peer: PublicKey, bytes: &[u8]) {
        match Message::decode(bytes) {
            Some(Message::Query(asking)) => {
                let answer = self.standing();
                let _ = self.sender.send(
                    Recipients::One(peer.clone()),
                    Message::Status(answer.clone()).encode(),
                    true,
                );
                // The asker may hold a later term than this device: a device
                // replaced while it could not reach the others learns it here.
                if !self.backup
                    && let Some(certificate) = asking.certificate.clone()
                    && self.learn(certificate)
                {
                    return;
                }
                self.yield_to(peer, asking, &answer);
            }
            Some(Message::Status(status)) => {
                self.heard.insert(peer, status);
            }
            // A partial answer would read as a fork to the asking device;
            // without an answer it records nothing.
            Some(Message::Ancestry { heights }) => match self.held_blocks(&heights) {
                Ok((floor, blocks)) => {
                    let blocks = Message::Blocks { floor, blocks };
                    let _ = self
                        .sender
                        .send(Recipients::One(peer), blocks.encode(), true);
                }
                Err(error) => tracing::warn!(
                    height = error.height,
                    %error,
                    "ancestry request left unanswered"
                ),
            },
            Some(Message::Blocks { .. }) | None => {}
        }
    }

    /// Note that this device answered `peer`, which asked with `asking`, and
    /// that the exchange lets the asker go on.
    ///
    /// The asker decides from the same two statuses, so a device that holds
    /// back stops whenever an exchange it answered lets the asker go on, even
    /// if its own question, asked at other heights, would have let it go on.
    fn yield_to(&mut self, peer: PublicKey, asking: Status, answer: &Status) {
        let Some(switching) = &self.switching else {
            return;
        };
        let listed = switching.devices.iter().any(|device| device.key == peer);
        if self.backup || !answer.waiting || !listed || self.view.demoted.borrow().is_some() {
            return;
        }
        let this = device_id(&switching.device_key.public_key());
        if super::contest::yields(device_id(&peer), &asking, this, answer) {
            self.yielded = Some((peer, asking));
        }
    }

    /// Store a certificate of a later term held by another device, if it
    /// verifies, and stop proposing for good. Returns whether it did.
    fn learn(&mut self, certificate: TermCertificate) -> bool {
        let Ok(this) = self.this_device() else {
            return false;
        };
        let change = certificate.change;
        if change.term <= self.seen() || change.holder == this || self.verify(&certificate).is_err()
        {
            return false;
        }
        if let Err(error) = self.store(certificate.clone()) {
            tracing::error!(%error, "term certificate could not be stored");
            return false;
        }
        tracing::warn!(
            term = change.term,
            cut = change.cut.height,
            "another device holds a later term; this device stops proposing"
        );
        self.hold.hold();
        // Blocks this device proposed before the hold still finalize here.
        // They are void in the new term, and the rewind that follows drops
        // them; refusing them now would stop the node.
        self.view.guard.raise(change.term, u64::MAX);
        self.view.contested.send_replace(None);
        self.view.demoted.send_replace(Some(certificate));
        true
    }

    /// Ask the others again while this device proposes.
    ///
    /// A device whose newest block is outside the window asks before its
    /// next proposal instead. Asking here as well would hold that question
    /// back: a device that does not answer costs each check the whole
    /// answer timeout, which can exceed the window.
    async fn recheck(&mut self) {
        if self.hold.is_held() || self.view.demoted.borrow().is_some() || !self.gate.fresh() {
            return;
        }
        if self.probe(false).await == Asked::Contested {
            self.gate.expire();
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
            waiting: self.holds_back(),
        }
    }

    /// Whether this device proposes nothing for now: a proposal waits for
    /// the others' answers, another device answered, or its newest block is
    /// too old for it to propose before it has asked.
    fn holds_back(&self) -> bool {
        self.asking || self.view.contested.borrow().is_some() || !self.gate.fresh()
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
        // A device that names itself renews its term: it settles a contest
        // in its favour, and needs no other device to confirm the cut.
        let renewal = successor == switching.device_key.public_key();
        if !renewal && switching.device(&successor).is_none() {
            return Err(TermRefusal::UnknownDevice(Box::new(successor)));
        }
        // A device that already gave the deployment up, or was replaced,
        // has no term to hand over, and a failure below must not let it propose.
        if let Some(refusal) = self.displaced(&this) {
            return Err(refusal);
        }
        let wait = switching.answer_timeout;
        let held = self.hold.is_held();
        let change = self.announce(successor, wait, renewal).await;
        if change.is_err() && !held {
            self.hold.release();
        }
        change
    }

    async fn announce(
        &mut self,
        successor: PublicKey,
        wait: Duration,
        renewal: bool,
    ) -> Result<TermChange, TermRefusal> {
        if !self.hold.settle(SETTLE).await {
            return Err(TermRefusal::Unsettled);
        }
        let cut = self.head();
        if !renewal && !self.confirmed(&successor, &cut, wait).await {
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
        #[cfg(feature = "fault-injection")]
        crate::crash::point(&self.data_dir, "handover-announced");
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
                Message::Query(self.standing()).encode(),
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
    ///
    /// A certificate stored without its block is waited for: the block is
    /// fetched from the device that built it. When that device is away the
    /// block never comes, and the cut stays below it: the term voids it, and
    /// the start under the term removes its certificate.
    async fn executed(&self, wait: Duration) -> Result<TermCut, TermRefusal> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let head = self.head();
            let above = (self.finalized)(head.height + 1).await;
            let expired = tokio::time::Instant::now() >= deadline;
            match above {
                Archived::Nothing => return Ok(head),
                Archived::Certificate if expired => return Ok(head),
                Archived::Block if expired => {
                    return Err(TermRefusal::NotAtCut {
                        head: head.height + 1,
                        cut: head.height,
                    });
                }
                Archived::Certificate | Archived::Block => tokio::time::sleep(POLL).await,
            }
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
        vera_permission::verify_term_certificate(certificate, &self.genesis_id, &policy)?;
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
                let renewal = self.record.handed_over == Some(change);
                if !self.backup && !renewal {
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
                #[cfg(feature = "fault-injection")]
                crate::crash::point(&self.data_dir, "takeover-accepted");
                self.record = record;
                Ok(())
            }
            Accept::Follow => {
                // A wake check or another device's question may have stored it already.
                if self.record.certificate.as_ref() != Some(&certificate) {
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
                    self.store(certificate)?;
                }
                self.locate(&change).await
            }
        }
    }

    /// Wait until this node's newest block is `cut`. The final block of a
    /// handover may still be on its way, and so may the block of a
    /// certificate stored above the cut. A certificate whose block has not
    /// come when the wait ends is void in the term.
    async fn reach(&self, cut: &TermCut, wait: Duration) -> Result<(), TermRefusal> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let head = self.head();
            let above = (self.finalized)(cut.height + 1).await;
            let expired = tokio::time::Instant::now() >= deadline;
            if head == *cut
                && (above == Archived::Nothing || (above == Archived::Certificate && expired))
            {
                return Ok(());
            }
            let waiting = head.height < cut.height || above == Archived::Certificate;
            if !waiting || expired {
                return Err(TermRefusal::NotAtCut {
                    head: head
                        .height
                        .max(cut.height + u64::from(above == Archived::Block)),
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
            ran: self.record.ran,
            seating: self.record.seating,
            resync: self.record.resync,
            followed: self.record.followed,
            common: None,
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
    /// this device must not propose, with three exceptions: a device in a
    /// lower term than the one this device holds was replaced, and learns of
    /// it from the question; a device that holds the certificate of this
    /// device's term was replaced by it; and a device that holds its
    /// proposals back stops neither a device that proposes nor, of two that
    /// hold back, the one with more finalized blocks, or with as many and the
    /// lower key. A device this one answered meanwhile, whose exchange lets
    /// it go on, stops this one as well, so the two exchanges cannot let both
    /// go on. `held` says whether a proposal waits for the answer. A
    /// certificate of a later term that verifies and is stored replaces this
    /// device for good; anything else is reported to the host and asked again
    /// at the next proposal.
    async fn probe(&mut self, held: bool) -> Asked {
        let (Some(switching), Some(probe), false) = (&self.switching, &self.probe, self.backup)
        else {
            return Asked::Clear;
        };
        let this = device_id(&switching.device_key.public_key());
        let (devices, probe) = (switching.devices.clone(), probe.clone());
        self.asking = held;
        self.yielded = None;
        let asking = self.standing();
        let question = Message::Query(asking.clone());
        let context = self.context.child("term_probes");
        let asked = futures::future::join_all(devices.into_iter().map(|device| {
            let (probe, question) = (probe.clone(), question.clone());
            let context = context.child("term_probe");
            async move {
                let answer = probe
                    .exchange(
                        context,
                        device.address,
                        &question,
                        |message| match message {
                            Message::Status(status) => Some(status),
                            _ => None,
                        },
                    )
                    .await;
                answer.map(|status| (device.key, status))
            }
        }));
        let mut asked = std::pin::pin!(asked);
        // A device asking this one at the same time is answered meanwhile.
        let answers = loop {
            tokio::select! {
                answers = &mut asked => break answers,
                message = self.receiver.recv() => match message {
                    Ok((peer, bytes)) => self.hear(peer, bytes.as_ref()),
                    Err(_) => break asked.await,
                },
            }
        };
        self.asking = false;
        if self.view.demoted.borrow().is_some() {
            return Asked::Replaced;
        }
        let answers: Vec<_> = answers.into_iter().flatten().collect();
        let seen = self.seen();
        let later = answers
            .iter()
            .filter_map(|(_, status)| status.certificate.clone())
            .filter(|certificate| {
                let change = &certificate.change;
                change.term > seen && change.holder != this && self.verify(certificate).is_ok()
            })
            .max_by_key(|certificate| certificate.change.term);
        if let Some(certificate) = later
            && self.learn(certificate)
        {
            return Asked::Replaced;
        }
        let contest = answers
            .into_iter()
            .find(|(device, status)| {
                super::contest::stops(this, &asking, device_id(device), status)
            })
            .or_else(|| self.yielded.take());
        let Some((device, status)) = contest else {
            self.view.contested.send_replace(None);
            // A device asked from here on must hear that this one proposes.
            if held {
                self.gate.cleared();
            }
            return Asked::Clear;
        };
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
