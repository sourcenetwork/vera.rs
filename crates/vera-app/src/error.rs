//! Application errors.

use thiserror::Error;

/// Errors raised while building, verifying, or applying a block.
#[derive(Debug, Error)]
pub enum AppError {
    /// The executor rejected the block.
    #[error("execution: {0}")]
    Execution(String),
    /// A transaction or state error returned by the executor.
    #[error("execution: {0}")]
    Executor(#[from] vera_executor::ExecutionError),
    /// A state batch operation failed.
    #[error("state: {0}")]
    State(#[from] vera_backend::BackendError),
    /// The computed roots differ from the block's.
    #[error("root mismatch: {0}")]
    RootMismatch(&'static str),
}

#[cfg(test)]
mod tests {
    use super::AppError;
    use vera_executor::ExecutionError;

    #[test]
    fn execution_error_keeps_its_variant() {
        let error = AppError::from(ExecutionError::InvalidTx("invalid nonce".into()));
        assert!(matches!(
            error,
            AppError::Executor(ExecutionError::InvalidTx(_))
        ));
    }
}
