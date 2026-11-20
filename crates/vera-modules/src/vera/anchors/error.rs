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
    /// A stored anchor record does not decode or names another deployment.
    #[error("anchor record is malformed")]
    MalformedRecord,
}
