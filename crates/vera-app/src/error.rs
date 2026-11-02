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

impl AppError {
    pub(crate) const fn is_local_state_failure(&self) -> bool {
        match self {
            Self::Executor(error) => error.is_local_state_failure(),
            Self::State(
                vera_backend::BackendError::Storage(_) | vera_backend::BackendError::NotInitialized,
            ) => true,
            _ => false,
        }
    }
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

    #[test]
    fn backend_failures_are_distinct_from_invalid_evidence() {
        assert!(
            AppError::State(vera_backend::BackendError::Storage("disk error".into()))
                .is_local_state_failure()
        );
        assert!(
            AppError::State(vera_backend::BackendError::NotInitialized).is_local_state_failure()
        );
        assert!(!AppError::RootMismatch("root").is_local_state_failure());
        assert!(
            !AppError::Executor(ExecutionError::InvalidTx("invalid".into()))
                .is_local_state_failure()
        );
    }
}
