//! Why a device does not switch.

use std::path::PathBuf;

use vera_domain::{PublicKey, TermCertificate, TermChange, TermError};

/// Why a device refuses to hand over, take over, follow or start in a term.
#[derive(Debug, thiserror::Error)]
pub enum TermRefusal {
    /// The node was started without [`crate::Switching`].
    #[error("switching the active device is not configured")]
    NotConfigured,
    /// The key is not one of the devices the node was configured with.
    #[error("device {0} is not one of the account's devices")]
    UnknownDevice(Box<PublicKey>),
    /// Only the active device hands the deployment over.
    #[error("this device is a backup")]
    Backup,
    /// Only a backup takes the deployment over.
    #[error("this device is the active device")]
    Active,
    /// A node keeps its keys in files, which a backup's directory must not hold.
    #[error("switching needs key material held by the host")]
    KeysInFiles,
    /// The successor did not report the handover's final block in time.
    #[error("the successor did not confirm block {height} in time")]
    SuccessorNotCurrent {
        /// Height of the final block.
        height: u64,
    },
    /// Blocks this device proposed did not finalize before the handover.
    #[error("proposed blocks did not finalize in time")]
    Unsettled,
    /// The certificate is not approved under the operator policy in this device's state.
    #[error("term certificate does not verify: {0}")]
    Certificate(#[from] TermError),
    /// The certificate names another device where this one was expected, or the reverse.
    #[error("term certificate names the wrong device as holder")]
    Holder,
    /// The certificate's term is not above the one this device holds.
    #[error("term {offered} is not above term {held}")]
    Stale {
        /// The certificate's term.
        offered: u64,
        /// The newest term this device holds or has seen in a block.
        held: u64,
    },
    /// This device's newest block is not the block the term builds on.
    #[error("this device is at block {head}, and the term builds on block {cut}")]
    NotAtCut {
        /// Height of this device's newest finalized block.
        head: u64,
        /// Height of the certificate's cut.
        cut: u64,
    },
    /// This device announced a handover and has not resumed.
    #[error("this device handed the deployment over at block {}", .0.cut.height)]
    HandedOver(Box<TermChange>),
    /// Another device holds a later term than this device is active in.
    #[error("another device holds term {}", .0.change.term)]
    Superseded(Box<TermCertificate>),
    /// The deployment's blocks are in a later term than this device holds.
    #[error("the deployment is in term {seen}, and this device holds term {held}")]
    Behind {
        /// Term of the newest block this device has.
        seen: u64,
        /// Term this device holds.
        held: u64,
    },
    /// A finalized block above the cut of the term this device holds is in a
    /// lower term: the device it came from was replaced.
    #[error("block {height} is in term {term}, below term {held} this device holds")]
    LowerTerm {
        /// Height of the refused block.
        height: u64,
        /// The block's term.
        term: u64,
        /// The term this device holds.
        held: u64,
    },
    /// The operator policy could not be read from this device's state.
    #[error("operator policy: {0}")]
    Policy(String),
    /// The term record in the data directory could not be read or written.
    #[error("term record {}: {source}", path.display())]
    Io {
        /// The record's path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The term record in the data directory does not decode.
    #[error("term record {}: {reason}", path.display())]
    Record {
        /// The record's path.
        path: PathBuf,
        /// Decoding failure.
        reason: String,
    },
    /// The node stopped before it answered.
    #[error("the node stopped")]
    Stopped,
}
