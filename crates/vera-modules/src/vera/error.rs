//! Vera module error types.

use thiserror::Error;

/// Errors produced by the Vera module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum VeraError {
    #[error("invalid threshold object: {reason}")]
    InvalidThresholdObject { reason: String },
    #[error("invalid ring request: {reason}")]
    InvalidRingRequest { reason: String },
    #[error("invalid node request: {reason}")]
    InvalidNodeRequest { reason: String },
    #[error("invalid administrative request: {reason}")]
    InvalidAdministrativeRequest { reason: String },

    #[error("JWS token not found: {token_hash}")]
    TokenNotFound { token_hash: String },

    #[error("JWS token already invalidated: {token_hash}")]
    TokenAlreadyInvalidated { token_hash: String },

    #[error("invalid JWS: {reason}")]
    InvalidJws { reason: String },

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("state error: {0}")]
    State(String),
}
