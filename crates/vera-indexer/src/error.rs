//! Error types for the indexer.

use thiserror::Error;

/// Errors that can occur during indexing operations.
#[derive(Debug, Error)]
pub enum IndexerError {
    /// Log query work or retained results exceed the service budget.
    #[error("log query limit exceeded; narrow the range or filter")]
    LogQueryLimit,

    /// Invalid block range for log filter.
    #[error("invalid block range: from {from} > to {to}")]
    InvalidBlockRange {
        /// Start of the range.
        from: u64,
        /// End of the range.
        to: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_block_range_display() {
        let err = IndexerError::InvalidBlockRange { from: 100, to: 50 };
        assert_eq!(err.to_string(), "invalid block range: from 100 > to 50");
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IndexerError>();
    }

    #[test]
    fn test_error_debug_impl() {
        let err = IndexerError::LogQueryLimit;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("LogQueryLimit"));
    }
}
