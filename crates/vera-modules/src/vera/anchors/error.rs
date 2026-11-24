//! Why an anchor submission or record is refused.

/// Errors of the anchor module and of anchor records read back.
///
/// A revision that is not finalized under the consensus key is refused by the
/// caller that verifies it, before the module sees it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    /// The finality artifacts exceed the anchor limit.
    #[error("anchored revision exceeds {} bytes", super::MAX_ANCHOR_ARTIFACT_BYTES)]
    TooLarge,
    /// The consensus key does not decode.
    #[error("consensus key does not decode")]
    InvalidConsensusKey,
    /// The revision is not higher than the deployment's latest anchor.
    #[error("revision {height} is not above the latest anchor at {latest}")]
    NotNewer {
        /// Height of the latest anchor.
        latest: u64,
        /// Height of the submitted revision.
        height: u64,
    },
    /// The revision's term is lower than the latest anchor's.
    #[error("revision term {term} is below the latest anchor's term {latest}")]
    LowerTerm {
        /// Term of the latest anchor.
        latest: u64,
        /// Term of the submitted revision.
        term: u64,
    },
    /// The revision is not shown to descend from the deployment's latest anchor.
    #[error("revision {height} is not shown to descend from the latest anchor at {latest}")]
    NotDescendant {
        /// Height of the latest anchor.
        latest: u64,
        /// Height of the submitted revision.
        height: u64,
    },
    /// The deployment has no anchor a fork could conflict with.
    #[error("the deployment has no anchor")]
    NoAnchor,
    /// The reported block does not conflict with the deployment's latest anchor.
    #[error("revision {height} is not shown to conflict with the latest anchor at {latest}")]
    NotAFork {
        /// Height of the latest anchor.
        latest: u64,
        /// Height of the reported revision.
        height: u64,
    },
    /// The fork is already recorded.
    #[error("the fork is already recorded")]
    ForkRecorded,
    /// The deployment is not registered for anchoring.
    #[error("the deployment is not registered")]
    NotRegistered,
    /// A registration names no genesis block, an invalid operator policy, or
    /// another genesis block than the deployment is registered with.
    #[error("the registration is invalid or names another genesis block")]
    InvalidRegistration,
    /// A grant names an invalid signer or a quota of zero.
    #[error("the submitter grant is invalid")]
    InvalidGrant,
    /// The signer has no grant to submit for the deployment.
    #[error("the signer has no grant to submit for the deployment")]
    NotGranted,
    /// The signer used its quota of submissions for the day.
    #[error("the signer used its {quota} submissions for the day")]
    QuotaExceeded {
        /// Submissions the grant allows in one day.
        quota: u32,
    },
    /// A stored anchor record does not decode or names another deployment.
    #[error("anchor record is malformed")]
    MalformedRecord,
}
