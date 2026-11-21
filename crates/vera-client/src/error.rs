//! Client error types.

use alloy_primitives::B256;

use crate::types::TransactionReceipt;

/// Errors returned by [`VeraClient`](crate::VeraClient) methods.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// JSON-RPC error returned by the node.
    #[error("RPC error ({code}): {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// Human-readable error message.
        message: String,
    },

    /// The client rejected work before sending because its request slots are occupied.
    #[error("client request capacity exhausted")]
    ClientCapacityExhausted,

    /// The server rejected work because temporary capacity is exhausted.
    #[error("RPC service busy: {0}")]
    ResourceBusy(String),

    /// The requested revision has no finalization certificate yet: the node has
    /// applied it, and a descendant that finalizes it is still to come. Retryable.
    #[error("finality pending: {0}")]
    FinalityPending(String),

    /// ABI decoding failed on a precompile response.
    #[error("ABI decode error: {0}")]
    AbiDecode(String),

    /// A module refused a native request. The request was executed and its
    /// sequence consumed; the receipt says why it had no effect.
    #[error("{refusal}")]
    Refused {
        /// The committed module and kind, with the module's message.
        refusal: vera_domain::Refusal,
        /// Full receipt for inspection.
        receipt: Box<TransactionReceipt>,
    },

    /// An EVM transaction was included but reverted.
    #[error("transaction reverted: status={status}")]
    TxReverted {
        /// EVM status code (0 = revert).
        status: u64,
        /// Full receipt for inspection.
        receipt: Box<TransactionReceipt>,
    },

    /// Receipt polling exhausted without finding the receipt.
    /// The submission was accepted and may still execute.
    #[error("receipt for {tx_hash} not available after {attempts} attempts")]
    ReceiptTimeout {
        /// Accepted submission whose receipt can still be read later.
        tx_hash: B256,
        /// Number of poll attempts made.
        attempts: u32,
    },

    /// Receipt polling failed after the submission was accepted, which may still execute.
    #[error("receipt for {tx_hash} could not be read: {source}")]
    ReceiptUnavailable {
        /// Accepted submission whose receipt can still be read later.
        tx_hash: B256,
        /// Failure of the last poll.
        source: Box<Self>,
    },

    /// A native request was sent but its reply was lost, so admission is unknown.
    ///
    /// The signer's sequence is unchanged and the request may still execute.
    /// Settle it with [`VeraClient::confirm_submission`](crate::VeraClient::confirm_submission)
    /// before signing different content.
    #[error("admission of {tx_hash} at sequence {sequence} is unknown: {source}")]
    SubmissionUnknown {
        /// Identifier of the signed request, whose receipt can be polled.
        tx_hash: B256,
        /// Sequence the request was signed with.
        sequence: u64,
        /// Transport failure that lost the reply.
        source: Box<Self>,
    },

    /// Transaction signing failed.
    #[error("signing error: {0}")]
    Signing(String),

    /// A term certificate does not verify under the certified operator policy.
    #[error(transparent)]
    Term(#[from] vera_domain::TermError),

    /// Durable submission state could not be read, validated or persisted.
    #[error("native worker state: {0}")]
    Worker(String),

    /// BLS operation failed.
    #[error("BLS error: {0}")]
    Bls(String),

    /// JSON-RPC response contained no `result` field.
    #[error("missing result in RPC response")]
    MissingResult,

    /// Response exceeded the transport byte limit.
    #[error("RPC response exceeds {0} bytes")]
    ResponseTooLarge(usize),

    /// Response metadata did not match the request.
    #[error("invalid RPC response: {0}")]
    InvalidResponse(&'static str),

    /// Permission evidence or evaluation failed.
    #[error(transparent)]
    Permission(#[from] vera_permission::PermissionError),

    /// Anchoring, an anchored snapshot or its freshness check failed.
    #[error(transparent)]
    Anchoring(#[from] crate::anchoring::AnchoringError),

    /// Finalization could not be verified against configured trust.
    #[error(transparent)]
    Finalization(#[from] vera_domain::LightBlockError),

    /// Receipt evidence did not match finalized execution.
    #[error(transparent)]
    Receipt(#[from] vera_domain::ReceiptResponseError),

    /// HTTP transport error.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ClientError {
    /// Whether a request was rejected for temporary capacity exhaustion.
    ///
    /// Callers must still bound retries and preserve submission identity.
    #[must_use]
    pub fn is_throttled(&self) -> bool {
        matches!(self, Self::ClientCapacityExhausted | Self::ResourceBusy(_))
            || matches!(self, Self::Transport(error) if error.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS))
    }

    pub(crate) fn from_rpc(error: &serde_json::Value) -> Self {
        let code = error
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let message = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let retryable = error.get("data").and_then(|data| data.get("retryable"))
            == Some(&serde_json::Value::Bool(true));
        if code == -32002 && retryable {
            Self::ResourceBusy(message)
        } else if code == -32006 && retryable {
            Self::FinalityPending(message)
        } else {
            Self::Rpc { code, message }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_finality_is_its_own_retryable_error() {
        let error = ClientError::from_rpc(&serde_json::json!({
            "code": -32006,
            "message": "finalization certificate not found for height 7 within retained proof limits",
            "data": {"retryable": true, "height": 7}
        }));
        assert!(matches!(error, ClientError::FinalityPending(_)));
        assert!(!error.is_throttled());
        let error = ClientError::from_rpc(&serde_json::json!({
            "code": -32006, "message": "pending",
        }));
        assert!(matches!(error, ClientError::Rpc { code: -32006, .. }));
    }

    #[test]
    fn remote_throttle_cannot_impersonate_local_capacity() {
        let error = ClientError::from_rpc(&serde_json::json!({
            "code": -32002,
            "message": "client request capacity exhausted",
            "data": {"retryable": true}
        }));
        assert!(matches!(error, ClientError::ResourceBusy(_)));
        assert!(error.is_throttled());
    }

    #[test]
    fn only_explicit_capacity_errors_are_throttled() {
        for (code, data, expected) in [
            (-32002, serde_json::json!({"retryable": true}), true),
            (-32002, serde_json::json!({"retryable": false}), false),
            (-32002, serde_json::json!({"retryable": "true"}), false),
            (-32002, serde_json::Value::Null, false),
            (-32602, serde_json::json!({"retryable": true}), false),
        ] {
            let error = ClientError::from_rpc(&serde_json::json!({
                "code": code, "message": "unavailable", "data": data,
            }));
            assert_eq!(error.is_throttled(), expected);
            if !expected {
                assert!(matches!(error, ClientError::Rpc { code: actual, .. } if actual == code));
            }
        }
    }

    #[test]
    fn rpc_error_display() {
        let err = ClientError::Rpc {
            code: -32600,
            message: "invalid request".into(),
        };
        assert_eq!(err.to_string(), "RPC error (-32600): invalid request");
    }

    #[test]
    fn missing_result_display() {
        let err = ClientError::MissingResult;
        assert_eq!(err.to_string(), "missing result in RPC response");
    }

    #[test]
    fn receipt_timeout_display() {
        let err = ClientError::ReceiptTimeout {
            tx_hash: B256::repeat_byte(0xab),
            attempts: 10,
        };
        assert_eq!(
            err.to_string(),
            format!(
                "receipt for 0x{} not available after 10 attempts",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn unknown_admission_names_the_submission_and_its_sequence() {
        let err = ClientError::SubmissionUnknown {
            tx_hash: B256::repeat_byte(0xcd),
            sequence: 7,
            source: Box::new(ClientError::MissingResult),
        };
        assert_eq!(
            err.to_string(),
            format!(
                "admission of 0x{} at sequence 7 is unknown: missing result in RPC response",
                "cd".repeat(32)
            )
        );
        assert!(!err.is_throttled());
    }

    #[test]
    fn abi_decode_display() {
        let err = ClientError::AbiDecode("bad selector".into());
        assert_eq!(err.to_string(), "ABI decode error: bad selector");
    }

    #[test]
    fn bls_error_display() {
        let err = ClientError::Bls("invalid key".into());
        assert_eq!(err.to_string(), "BLS error: invalid key");
    }
}
