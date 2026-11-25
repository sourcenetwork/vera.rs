//! Execution receipts committed by finalized revisions.

use alloy_primitives::{B256, Log};

use crate::Refusal;

/// What executing one native request produced.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExecutionReceipt {
    /// Request identifier.
    pub tx_hash: B256,
    /// Whether the module call ran to completion.
    pub success: bool,
    /// Gas used by this request alone.
    pub gas_used: u64,
    /// Gas used in the block up to and including this request.
    pub cumulative_gas_used: u64,
    /// Events the call emitted.
    pub logs: Vec<Log>,
    /// Why a module refused the request; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
}

impl ExecutionReceipt {
    /// Create a new execution receipt.
    pub const fn new(
        tx_hash: B256,
        success: bool,
        gas_used: u64,
        cumulative_gas_used: u64,
        logs: Vec<Log>,
    ) -> Self {
        Self {
            tx_hash,
            success,
            gas_used,
            cumulative_gas_used,
            logs,
            refusal: None,
        }
    }

    /// The same receipt, recording why its request was refused.
    #[must_use]
    pub fn with_refusal(mut self, refusal: Option<Refusal>) -> Self {
        self.refusal = refusal;
        self
    }

    /// Returns whether the request succeeded.
    pub const fn success(&self) -> bool {
        self.success
    }

    /// Returns the cumulative gas used up to and including this request.
    pub const fn cumulative_gas_used(&self) -> u64 {
        self.cumulative_gas_used
    }

    /// Returns the logs emitted during execution.
    pub fn logs(&self) -> &[Log] {
        &self.logs
    }
}
