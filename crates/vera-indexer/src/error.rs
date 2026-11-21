//! Error types for the indexer.

use thiserror::Error;

/// Errors that can occur while reading indexed execution history.
#[derive(Debug, Error)]
pub enum IndexerError {
    /// The encoded records of one read exceed its byte budget.
    #[error("archive read exceeds its byte budget")]
    ReadLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IndexerError>();
    }
}
