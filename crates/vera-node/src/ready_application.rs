//! Keep speculative DKG work behind recovered execution state.

use commonware_consensus::{Application, Handoff, Heightable as _, marshal::ancestry::Ancestry};
use commonware_cryptography::Digested;
use commonware_runtime::tokio::Context;
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct ReadyApplication<A> {
    inner: A,
    ready: watch::Receiver<bool>,
    hold: crate::ProposalHold,
    gate: crate::term::WakeGate,
    #[cfg(feature = "fault-injection")]
    stall: Option<std::path::PathBuf>,
}

impl<A> ReadyApplication<A> {
    pub(crate) fn new(
        inner: A,
        hold: crate::ProposalHold,
        gate: crate::term::WakeGate,
    ) -> (Self, watch::Sender<bool>) {
        let (sender, ready) = watch::channel(false);
        (
            Self {
                inner,
                ready,
                hold,
                gate,
                #[cfg(feature = "fault-injection")]
                stall: None,
            },
            sender,
        )
    }

    /// Lets a test hold a staged block back; see `term::fault::stall_staged`.
    #[cfg(feature = "fault-injection")]
    pub(crate) fn with_stall(mut self, directory: std::path::PathBuf) -> Self {
        self.stall = Some(directory);
        self
    }
}

impl<A> Application<Context> for ReadyApplication<A>
where
    A: Application<Context>,
    A::Context: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;
    type Input = A::Input;

    async fn prepare(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Handoff<Digested<Self::Block>> {
        // A block built ahead of its turn would escape a hold and the wake check.
        if !*self.ready.borrow() || self.hold.is_held() || !self.gate.fresh() {
            return Handoff::Wait;
        }
        // A staged block reaches consensus without a further request, so it
        // is counted as a proposal and dropped when a hold begins during its build.
        let building = self.hold.building();
        let hold = self.hold.clone();
        let built = async {
            let handoff = self.inner.prepare(context, ancestry, input).await;
            #[cfg(feature = "fault-injection")]
            if let (Handoff::Stage(_), Some(directory)) = (&handoff, &self.stall) {
                crate::term::fault::stall_staged(directory).await;
            }
            handoff
        };
        let handoff = tokio::select! {
            biased;
            () = hold.held() => Handoff::Wait,
            handoff = built => handoff,
        };
        let height = match &handoff {
            Handoff::Stage(block) | Handoff::Vote(block) => block.height().get(),
            Handoff::Wait => return Handoff::Wait,
        };
        // The build can outlast the freshness window; the request that
        // follows asks the other devices first.
        if !self.gate.fresh() {
            return Handoff::Wait;
        }
        self.hold.record(height);
        self.gate.proposed();
        drop(building);
        handoff
    }

    async fn propose(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Digested<Self::Block>> {
        // Declining here would cost the whole view: a validator that starts as
        // leader would wait out the leader timeout before its next proposal.
        // Consensus drops this request if recovery outlasts the view.
        if self.ready.wait_for(|ready| *ready).await.is_err() {
            return None;
        }
        // A host that is stopping must not be left with a vote whose
        // certificate it has not stored; consensus drops the unanswered request.
        let building = self.hold.building();
        let proposal = tokio::select! {
            biased;
            () = self.hold.held() => {
                drop(building);
                return std::future::pending().await;
            }
            proposal = async {
                // A device that may have been replaced asks before it builds.
                self.gate.pass().await;
                let proposal = self.inner.propose(context, ancestry, input).await;
                // The build can wait for a first request, and the machine can
                // sleep inside that wait: ask again before the block leaves.
                if proposal.is_some() {
                    self.gate.pass().await;
                }
                proposal
            } => proposal,
        };
        if let Some(block) = &proposal {
            self.hold.record(block.height().get());
            self.gate.proposed();
        }
        drop(building);
        proposal
    }

    async fn verify(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        if self.ready.wait_for(|ready| *ready).await.is_err() {
            // Startup failure cannot establish that a peer's proposal is invalid.
            return std::future::pending().await;
        }
        self.inner.verify(context, ancestry).await
    }
}

#[cfg(test)]
#[path = "ready_application_tests.rs"]
mod tests;
