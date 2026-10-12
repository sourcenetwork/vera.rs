//! JSON-RPC error types following Ethereum error code conventions.

use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

/// JSON-RPC error codes following Ethereum conventions.
pub mod codes {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i32 = -32700;
    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid method parameter(s).
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i32 = -32603;

    /// Server error (reserved range: -32000 to -32099).
    pub const SERVER_ERROR: i32 = -32000;
    /// Resource not found.
    pub const RESOURCE_NOT_FOUND: i32 = -32001;
    /// Resource unavailable.
    pub const RESOURCE_UNAVAILABLE: i32 = -32002;
    /// Transaction rejected.
    pub const TRANSACTION_REJECTED: i32 = -32003;
    /// Method not supported.
    pub const METHOD_NOT_SUPPORTED: i32 = -32004;
    /// Request limit exceeded.
    pub const LIMIT_EXCEEDED: i32 = -32005;
    /// Execution error (revert, out of gas, etc.).
    pub const EXECUTION_ERROR: i32 = -32015;
}

/// Admission failures before an operation enters the pending queue.
#[derive(Debug, Clone, Error)]
pub enum TxSubmitError {
    /// Committed state has not finished opening.
    #[error("node is still starting")]
    NotReady,
    /// The pending request count or byte budget is full.
    #[error("pending request capacity reached")]
    AtCapacity,
    /// The request failed admission validation.
    #[error("{0}")]
    Rejected(String),
}

impl From<TxSubmitError> for ErrorObjectOwned {
    fn from(error: TxSubmitError) -> Self {
        match error {
            TxSubmitError::Rejected(message) => RpcError::InvalidTransaction(message).into(),
            error @ (TxSubmitError::NotReady | TxSubmitError::AtCapacity) => {
                ErrorObjectOwned::owned(
                    codes::RESOURCE_UNAVAILABLE,
                    error.to_string(),
                    Some(serde_json::json!({"retryable": true})),
                )
            }
        }
    }
}

/// RPC-specific errors that can occur during request handling.
#[derive(Debug, Error)]
pub enum RpcError {
    /// All blocking history readers are occupied.
    #[error("history service busy; retry later")]
    HistoryBusy,
    /// Request work or response exceeds the service budget.
    #[error("request limit exceeded: {0}")]
    LimitExceeded(String),

    /// Block not found.
    #[error("block not found")]
    BlockNotFound,

    /// Transaction not found.
    #[error("transaction not found")]
    TransactionNotFound,

    /// Account not found.
    #[error("account not found: {0}")]
    AccountNotFound(String),

    /// Invalid block number.
    #[error("invalid block number: {0}")]
    InvalidBlockNumber(String),

    /// Invalid transaction.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Invalid method parameters.
    #[error("invalid params: {0}")]
    InvalidParams(String),

    /// Execution failed.
    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    /// Execution reverted with ABI-encoded revert data.
    #[error("execution reverted")]
    ExecutionReverted {
        /// Hex-encoded revert data (with 0x prefix).
        data: String,
    },

    /// State database error.
    #[error("state error: {0}")]
    StateError(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Method not implemented.
    #[error("method not implemented")]
    NotImplemented,
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        match &err {
            RpcError::HistoryBusy => ErrorObjectOwned::owned(
                codes::RESOURCE_UNAVAILABLE,
                err.to_string(),
                Some(serde_json::json!({"retryable": true})),
            ),
            RpcError::ExecutionReverted { data } => {
                ErrorObjectOwned::owned(codes::EXECUTION_ERROR, err.to_string(), Some(data.clone()))
            }
            _ => {
                let (code, message) = match &err {
                    RpcError::LimitExceeded(_) => (codes::LIMIT_EXCEEDED, err.to_string()),
                    RpcError::BlockNotFound => (codes::RESOURCE_NOT_FOUND, err.to_string()),
                    RpcError::TransactionNotFound => (codes::RESOURCE_NOT_FOUND, err.to_string()),
                    RpcError::AccountNotFound(_) => (codes::RESOURCE_NOT_FOUND, err.to_string()),
                    RpcError::InvalidBlockNumber(_) => (codes::INVALID_PARAMS, err.to_string()),
                    RpcError::InvalidTransaction(_) => (codes::INVALID_PARAMS, err.to_string()),
                    RpcError::InvalidParams(_) => (codes::INVALID_PARAMS, err.to_string()),
                    RpcError::ExecutionFailed(_) => (codes::EXECUTION_ERROR, err.to_string()),
                    RpcError::StateError(_) => (codes::INTERNAL_ERROR, err.to_string()),
                    RpcError::Internal(_) => (codes::INTERNAL_ERROR, err.to_string()),
                    RpcError::NotImplemented => (codes::METHOD_NOT_SUPPORTED, err.to_string()),
                    RpcError::ExecutionReverted { .. } | RpcError::HistoryBusy => unreachable!(),
                };
                ErrorObjectOwned::owned(code, message, None::<()>)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_capacity_and_startup_are_retryable_but_rejections_are_not() {
        for error in [TxSubmitError::AtCapacity, TxSubmitError::NotReady] {
            let rpc: ErrorObjectOwned = error.into();
            assert_eq!(rpc.code(), codes::RESOURCE_UNAVAILABLE);
            let data: serde_json::Value = serde_json::from_str(rpc.data().unwrap().get()).unwrap();
            assert_eq!(data, serde_json::json!({"retryable": true}));
        }
        let rejected: ErrorObjectOwned = TxSubmitError::Rejected("invalid signature".into()).into();
        assert_eq!(rejected.code(), codes::INVALID_PARAMS);
        assert!(rejected.data().is_none());
    }

    #[test]
    fn error_codes_standard_values() {
        assert_eq!(codes::PARSE_ERROR, -32700);
        assert_eq!(codes::INVALID_REQUEST, -32600);
        assert_eq!(codes::METHOD_NOT_FOUND, -32601);
        assert_eq!(codes::INVALID_PARAMS, -32602);
        assert_eq!(codes::INTERNAL_ERROR, -32603);
    }

    #[test]
    fn error_codes_server_range() {
        assert_eq!(codes::SERVER_ERROR, -32000);
        assert_eq!(codes::RESOURCE_NOT_FOUND, -32001);
        assert_eq!(codes::RESOURCE_UNAVAILABLE, -32002);
        assert_eq!(codes::TRANSACTION_REJECTED, -32003);
        assert_eq!(codes::METHOD_NOT_SUPPORTED, -32004);
        assert_eq!(codes::LIMIT_EXCEEDED, -32005);
        assert_eq!(codes::EXECUTION_ERROR, -32015);
    }

    #[test]
    fn rpc_error_display_block_not_found() {
        let err = RpcError::BlockNotFound;
        assert_eq!(err.to_string(), "block not found");
    }

    #[test]
    fn rpc_error_display_transaction_not_found() {
        let err = RpcError::TransactionNotFound;
        assert_eq!(err.to_string(), "transaction not found");
    }

    #[test]
    fn rpc_error_display_account_not_found() {
        let err = RpcError::AccountNotFound("0x1234".to_string());
        assert_eq!(err.to_string(), "account not found: 0x1234");
    }

    #[test]
    fn rpc_error_display_invalid_block_number() {
        let err = RpcError::InvalidBlockNumber("not a number".to_string());
        assert_eq!(err.to_string(), "invalid block number: not a number");
    }

    #[test]
    fn rpc_error_display_invalid_transaction() {
        let err = RpcError::InvalidTransaction("bad sig".to_string());
        assert_eq!(err.to_string(), "invalid transaction: bad sig");
    }

    #[test]
    fn rpc_error_display_execution_failed() {
        let err = RpcError::ExecutionFailed("out of gas".to_string());
        assert_eq!(err.to_string(), "execution failed: out of gas");
    }

    #[test]
    fn rpc_error_display_state_error() {
        let err = RpcError::StateError("db locked".to_string());
        assert_eq!(err.to_string(), "state error: db locked");
    }

    #[test]
    fn rpc_error_display_internal() {
        let err = RpcError::Internal("unexpected".to_string());
        assert_eq!(err.to_string(), "internal error: unexpected");
    }

    #[test]
    fn rpc_error_display_not_implemented() {
        let err = RpcError::NotImplemented;
        assert_eq!(err.to_string(), "method not implemented");
    }

    #[test]
    fn rpc_error_to_error_object_block_not_found() {
        let err = RpcError::BlockNotFound;
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::RESOURCE_NOT_FOUND);
        assert_eq!(obj.message(), "block not found");
    }

    #[test]
    fn rpc_error_to_error_object_transaction_not_found() {
        let err = RpcError::TransactionNotFound;
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::RESOURCE_NOT_FOUND);
        assert_eq!(obj.message(), "transaction not found");
    }

    #[test]
    fn rpc_error_to_error_object_account_not_found() {
        let err = RpcError::AccountNotFound("0xabc".to_string());
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::RESOURCE_NOT_FOUND);
        assert!(obj.message().contains("0xabc"));
    }

    #[test]
    fn rpc_error_to_error_object_invalid_block_number() {
        let err = RpcError::InvalidBlockNumber("bad".to_string());
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::INVALID_PARAMS);
    }

    #[test]
    fn rpc_error_to_error_object_invalid_transaction() {
        let err = RpcError::InvalidTransaction("nope".to_string());
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::INVALID_PARAMS);
    }

    #[test]
    fn rpc_error_to_error_object_execution_failed() {
        let err = RpcError::ExecutionFailed("reverted".to_string());
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::EXECUTION_ERROR);
    }

    #[test]
    fn rpc_error_to_error_object_state_error() {
        let err = RpcError::StateError("corrupt".to_string());
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::INTERNAL_ERROR);
    }

    #[test]
    fn rpc_error_to_error_object_internal() {
        let err = RpcError::Internal("oops".to_string());
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::INTERNAL_ERROR);
    }

    #[test]
    fn rpc_error_to_error_object_not_implemented() {
        let err = RpcError::NotImplemented;
        let obj: ErrorObjectOwned = err.into();
        assert_eq!(obj.code(), codes::METHOD_NOT_SUPPORTED);
    }

    #[test]
    fn rpc_error_debug() {
        let err = RpcError::BlockNotFound;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("BlockNotFound"));
    }
}
