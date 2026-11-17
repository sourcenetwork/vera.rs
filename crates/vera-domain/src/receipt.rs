//! Execution receipts committed by finalized revisions.

use alloy_consensus::{Eip658Value, Receipt};
use alloy_primitives::{Address, B256, Log};

use crate::Refusal;

/// Receipt for a single transaction execution.
///
/// Wraps [`alloy_consensus::Receipt`] with additional execution metadata
/// that is not part of the consensus receipt (tx hash, per-tx gas, contract address).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExecutionReceipt {
    /// Transaction hash.
    pub tx_hash: B256,
    /// The consensus receipt containing status, cumulative gas, and logs.
    pub receipt: Receipt<Log>,
    /// Gas used by this transaction alone (not cumulative).
    pub gas_used: u64,
    /// Contract address if this was a contract creation.
    pub contract_address: Option<Address>,
    /// Why a module refused a native request; absent on success and for EVM requests.
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
        contract_address: Option<Address>,
    ) -> Self {
        Self {
            tx_hash,
            receipt: Receipt {
                status: Eip658Value::Eip658(success),
                cumulative_gas_used,
                logs,
            },
            gas_used,
            contract_address,
            refusal: None,
        }
    }

    /// The same receipt, recording why its native request was refused.
    #[must_use]
    pub fn with_refusal(mut self, refusal: Option<Refusal>) -> Self {
        self.refusal = refusal;
        self
    }

    /// Returns whether the transaction succeeded.
    pub const fn success(&self) -> bool {
        self.receipt.status.coerce_status()
    }

    /// Returns the cumulative gas used up to and including this transaction.
    pub const fn cumulative_gas_used(&self) -> u64 {
        self.receipt.cumulative_gas_used
    }

    /// Returns the logs emitted during execution.
    pub fn logs(&self) -> &[Log] {
        &self.receipt.logs
    }
}
