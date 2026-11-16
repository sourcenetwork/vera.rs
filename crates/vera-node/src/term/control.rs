//! The host's handle on a running node's term.

use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot, watch};
use vera_app::TermGuard;
use vera_domain::{PublicKey, TermCertificate, TermChange};

use super::TermRefusal;

type Reply<T> = oneshot::Sender<Result<T, TermRefusal>>;

/// How a device accepts a term certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Accept {
    /// As the certificate's holder: this backup becomes the active device.
    TakeOver,
    /// As any other device: it follows the holder.
    Follow,
}

pub(crate) enum Command {
    /// Hold proposals back and name the final block for `successor`.
    HandOver {
        successor: PublicKey,
        reply: Reply<TermChange>,
    },
    /// Undo an announced handover.
    Resume { reply: Reply<()> },
    /// The change a certificate must approve for this backup to take over.
    Offer { reply: Reply<TermChange> },
    /// Verify a certificate against this device's state and store it.
    Accept {
        certificate: Box<TermCertificate>,
        role: Accept,
        reply: Reply<()>,
    },
}

/// What the host reads without asking the node.
#[derive(Debug, Default)]
pub(crate) struct View {
    pub(crate) guard: TermGuard,
    pub(crate) certificate: RwLock<Option<TermCertificate>>,
    pub(crate) demoted: watch::Sender<Option<TermCertificate>>,
}

/// The host's side: reads the term and asks the node to change it.
#[derive(Clone, Debug)]
pub(crate) struct TermControl {
    commands: mpsc::UnboundedSender<Command>,
    view: Arc<View>,
}

/// The node's side, handed to it when it starts.
#[derive(Debug)]
pub struct TermSeat {
    pub(crate) commands: mpsc::UnboundedReceiver<Command>,
    pub(crate) view: Arc<View>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::HandOver { .. } => "HandOver",
            Self::Resume { .. } => "Resume",
            Self::Offer { .. } => "Offer",
            Self::Accept { .. } => "Accept",
        })
    }
}

impl TermControl {
    pub(crate) fn new() -> (Self, TermSeat) {
        let (sender, commands) = mpsc::unbounded_channel();
        let view = Arc::new(View::default());
        (
            Self {
                commands: sender,
                view: view.clone(),
            },
            TermSeat { commands, view },
        )
    }

    pub(crate) fn term(&self) -> u64 {
        self.view.guard.term()
    }

    pub(crate) fn certificate(&self) -> Option<TermCertificate> {
        self.view.certificate.read().clone()
    }

    /// Resolves with the certificate of a later term held by another device.
    pub(crate) async fn demoted(&self) -> TermCertificate {
        let mut demoted = self.view.demoted.subscribe();
        match demoted.wait_for(Option::is_some).await {
            Ok(certificate) => certificate
                .clone()
                .expect("a demotion carries its certificate"),
            Err(_) => std::future::pending().await,
        }
    }

    pub(crate) async fn hand_over(&self, successor: PublicKey) -> Result<TermChange, TermRefusal> {
        self.ask(|reply| Command::HandOver { successor, reply })
            .await
    }

    pub(crate) async fn resume(&self) -> Result<(), TermRefusal> {
        self.ask(|reply| Command::Resume { reply }).await
    }

    pub(crate) async fn offer(&self) -> Result<TermChange, TermRefusal> {
        self.ask(|reply| Command::Offer { reply }).await
    }

    pub(crate) async fn accept(
        &self,
        certificate: TermCertificate,
        role: Accept,
    ) -> Result<(), TermRefusal> {
        self.ask(|reply| Command::Accept {
            certificate: Box::new(certificate),
            role,
            reply,
        })
        .await
    }

    async fn ask<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T, TermRefusal> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(command(reply))
            .map_err(|_| TermRefusal::Stopped)?;
        answer.await.map_err(|_| TermRefusal::Stopped)?
    }
}
