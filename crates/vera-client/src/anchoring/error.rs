//! Why anchoring, a snapshot or its freshness check failed.

use vera_domain::{LightBlockError, Refusal};
use vera_modules::vera::anchors::AnchorError;
use vera_permission::PermissionError;

/// Errors of anchoring and of anchored snapshot verification.
#[derive(Debug, thiserror::Error)]
pub enum AnchoringError {
    /// The snapshot or its revision exceeds the anchoring limits.
    #[error("snapshot exceeds the anchoring limits")]
    TooLarge,
    /// Policy or record evidence did not verify.
    #[error(transparent)]
    Evidence(#[from] PermissionError),
    /// A revision is not finalized under the expected key.
    #[error(transparent)]
    Finality(#[from] LightBlockError),
    /// An anchor record is malformed or names another deployment.
    #[error(transparent)]
    Record(#[from] AnchorError),
    /// The anchoring deployment holds no anchor for the deployment.
    #[error("the deployment has no anchor")]
    NoAnchor,
    /// The snapshot's revision is not the revision its anchor records.
    #[error("snapshot revision {revision} is not the anchored revision {anchored}")]
    NotAnchored {
        /// Height of the snapshot's revision.
        revision: u64,
        /// Height of the anchored revision.
        anchored: u64,
    },
    /// A newer anchor of the deployment supersedes the snapshot.
    #[error("snapshot anchor {held} is superseded by anchor {latest}")]
    Stale {
        /// Sequence of the snapshot's anchor.
        held: u64,
        /// Sequence of the newer anchor.
        latest: u64,
    },
    /// A term the deployment's operators certified voided the snapshot's anchor.
    #[error("snapshot anchor {held} is above the cut of term {term}")]
    Superseded {
        /// Sequence of the snapshot's anchor.
        held: u64,
        /// The term that voided it.
        term: u64,
    },
    /// Two anchor records with one sequence differ in revision or order.
    #[error("anchor records with sequence {0} disagree")]
    Conflict(u64),
    /// The anchoring deployment refused the anchor.
    #[error("anchor refused: {0}")]
    Refused(Refusal),
    /// The anchor's receipt was not certified within the wait.
    #[error("anchor receipt not certified in time")]
    Unconfirmed,
}
