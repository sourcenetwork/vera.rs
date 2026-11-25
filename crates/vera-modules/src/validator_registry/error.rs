//! ValidatorRegistry error types.

use thiserror::Error;

/// Errors produced by the ValidatorRegistry module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum ValidatorRegistryError {
    #[error("validator already exists: {0}")]
    ValidatorAlreadyExists(String),

    #[error("validator not found: {0}")]
    ValidatorNotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid p2p address: {0}")]
    InvalidP2PAddress(String),

    #[error("membership change would leave no active participants")]
    EmptyCommittee,

    #[error("membership limit reached: {0}")]
    MembershipLimit(u32),

    #[error("epoch capacity permits at most {0} active participants")]
    EpochCapacity(u32),

    #[error("consensus key is already registered")]
    DuplicateConsensusKey,

    #[error("state error: {0}")]
    State(String),

    /// Stored registry state that does not read back: the node's own fault.
    #[error("registry state is unreadable: {0}")]
    Corrupt(String),
}
