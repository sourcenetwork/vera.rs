//! ACP module error types.

use thiserror::Error;

/// Errors produced by the ACP module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum AcpError {
    #[error("policy not found: {id}")]
    PolicyNotFound { id: String },

    #[error("invalid policy: {reason}")]
    InvalidPolicy { reason: String },

    #[error("access denied for policy {policy_id}")]
    AccessDenied { policy_id: String },

    #[error("invalid access request: {reason}")]
    InvalidAccessRequest { reason: String },

    #[error("object not registered: {resource}/{object_id}")]
    ObjectNotRegistered { resource: String, object_id: String },

    #[error("object already registered: {resource}/{object_id}")]
    ObjectAlreadyRegistered { resource: String, object_id: String },

    #[error("commitment not found: {id}")]
    CommitmentNotFound { id: u64 },

    #[error("commitment expired: {id}")]
    CommitmentExpired { id: u64 },

    #[error("invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("invalid bearer token: {reason}")]
    InvalidBearerToken { reason: String },

    #[error("replay detected: payload already processed")]
    ReplayDetected,

    #[error("expiration delta {delta} exceeds limit {max}")]
    ExpirationDeltaTooLarge { delta: u64, max: u64 },

    #[error("command expired at height {height}")]
    CommandExpired { height: u64 },

    #[error("policy creation work allowance exceeded")]
    PolicyCreateBudgetExceeded,

    #[error("policy edit work allowance exceeded")]
    PolicyEditBudgetExceeded,

    #[error("query work allowance exceeded")]
    QueryBudgetExceeded,

    #[error("permission work allowance exceeded")]
    PermissionBudgetExceeded,

    #[error("state error: {0}")]
    State(String),
}
