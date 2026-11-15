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

    #[error("policy creation work allowance exceeded")]
    PolicyCreateBudgetExceeded,

    #[error("policy edit work allowance exceeded")]
    PolicyEditBudgetExceeded,

    #[error("query work allowance exceeded")]
    QueryBudgetExceeded,

    #[error("command work allowance exceeded")]
    CommandBudgetExceeded,

    #[error("permission work allowance exceeded")]
    PermissionBudgetExceeded,

    #[error("state error: {0}")]
    State(String),
}
