//! Errors reading, decoding and changing ACP records, and evaluating over them.

/// A record read, decode, write or evaluation that has no answer. Never a denial.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// A read or write this store cannot serve: missing proof coverage, an
    /// exhausted allowance, or a write to a read-only store.
    #[error("record unavailable: {0}")]
    Unavailable(String),
    /// Stored state that does not read back as a valid record.
    #[error("invalid record: {0}")]
    Invalid(String),
    /// A record that does not encode or decode.
    #[error("record encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    /// The policy has no such resource.
    #[error("resource `{0}` is not in the policy")]
    UnknownResource(String),
    /// The policy's resource has no such relation or permission.
    #[error("resource `{resource}` has no relation `{relation}`")]
    UnknownRelation {
        /// The resource.
        resource: String,
        /// The relation or permission.
        relation: String,
    },
    /// Policy evaluation over the records failed.
    #[error("permission evaluation: {0}")]
    Evaluation(String),
}

impl RecordError {
    /// Stored state that does not read back.
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
    }

    /// A read or write this store cannot serve.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable(reason.into())
    }
}

/// The result of a record operation.
pub type Result<T> = std::result::Result<T, RecordError>;
