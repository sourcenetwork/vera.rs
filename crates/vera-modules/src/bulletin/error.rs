//! Bulletin module error types.

use thiserror::Error;

/// Errors produced by the Bulletin module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum BulletinError {
    #[error("namespace must be nonempty")]
    InvalidNamespace,

    #[error("namespace identifier must not exceed {0} bytes")]
    NamespaceTooLong(usize),

    #[error("post payload must be between 1 and {0} bytes")]
    PostPayloadTooLarge(usize),

    #[error("post proof must not exceed {0} bytes")]
    PostProofTooLarge(usize),

    #[error("post artifact must not exceed {0} bytes")]
    PostArtifactTooLarge(usize),

    #[error("namespace not found: {namespace}")]
    NamespaceNotFound { namespace: String },

    #[error("namespace already exists: {namespace}")]
    NamespaceAlreadyExists { namespace: String },

    #[error("post not found: {namespace}/{id}")]
    PostNotFound { namespace: String, id: String },

    #[error("post already exists: {namespace}/{id}")]
    PostAlreadyExists { namespace: String, id: String },

    #[error("not a collaborator on namespace {namespace}")]
    NotCollaborator { namespace: String },

    #[error("collaborator already exists: {namespace}/{did}")]
    CollaboratorAlreadyExists { namespace: String, did: String },

    #[error("collaborator not found: {namespace}/{did}")]
    CollaboratorNotFound { namespace: String, did: String },

    #[error("invalid post payload: payload must be non-empty")]
    InvalidPostPayload,

    #[error("policy not initialized")]
    PolicyNotInitialized,

    #[error("failed to initialize module policy: {0}")]
    PolicyInitFailed(String),

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("invalid glob pattern: {pattern}")]
    InvalidGlob { pattern: String },

    #[error("bulletin query budget exceeded; use certified native pages")]
    QueryLimit,

    #[error("state error: {0}")]
    State(String),
}
