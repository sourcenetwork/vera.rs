//! Execution outcome types.

use alloy_primitives::B256;
pub use vera_domain::ExecutionReceipt;

/// Result of executing a block's transactions.
#[derive(Clone, Debug, Default)]
pub struct ExecutionOutcome {
    /// Transaction receipts.
    pub receipts: Vec<ExecutionReceipt>,
    /// Total gas used by all transactions.
    pub gas_used: u64,
    /// Module state root after execution. The executor leaves it zero:
    /// ordered storage sets it from its authenticated partitions.
    pub module_state_root: B256,
    /// Indices of the input requests that were executed.
    ///
    /// During block building, requests that fail a check (a sequence that is
    /// not the signer's next, a signature that does not verify) are skipped.
    /// The proposer includes only these requests in the block so verifiers
    /// see a consistent set. `None` when verifying: every request executed.
    pub executed_tx_indices: Option<Vec<usize>>,
    /// Indices of the inputs block building found are not native requests.
    ///
    /// Waiting cannot cure them, unlike a request deferred by the block gas
    /// budget or one whose sequence is still ahead of its signer. The
    /// proposer drops them from its pending pool so they cannot occupy every
    /// later proposal.
    pub rejected_tx_indices: Vec<usize>,
}

impl ExecutionOutcome {
    /// Create a new empty execution outcome.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            receipts: Vec::new(),
            gas_used: 0,
            module_state_root: B256::ZERO,
            executed_tx_indices: None,
            rejected_tx_indices: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_outcome_default() {
        let outcome = ExecutionOutcome::new();
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.gas_used, 0);
    }
}
