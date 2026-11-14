//! Errors from loading and interpreting a genesis file.

/// Errors from genesis loading.
#[derive(Debug, thiserror::Error)]
pub enum VeraGenesisError {
    /// IO error reading the genesis file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Error parsing address or balance values.
    #[error("parse error: {0}")]
    Parse(String),
}
