//! Error types for the identity crate

use thiserror::Error;

/// Result type alias for identity operations
pub type Result<T> = std::result::Result<T, Error>;

/// Identity-specific error types
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid DID format
    #[error("invalid DID: {0}")]
    InvalidDid(String),
}
