//! Execution outcome types.

use alloy_primitives::B256;
pub use vera_domain::ExecutionReceipt;
use vera_qmdb::ChangeSet;

/// Result of executing a block's transactions.
#[derive(Clone, Debug, Default)]
pub struct ExecutionOutcome {
    /// State changes from execution.
    pub changes: ChangeSet,
    /// Transaction receipts.
    pub receipts: Vec<ExecutionReceipt>,
    /// Total gas used by all transactions.
    pub gas_used: u64,
    /// Module state root after execution. The executor leaves it zero:
    /// ordered storage sets it from its authenticated partitions.
    pub module_state_root: B256,
    /// Indices of input txs that were actually executed.
    ///
    /// During block building, txs that fail validation (e.g. NonceTooLow) are
    /// skipped.  The proposer must include only these txs in the block so
    /// verifiers see a consistent set.  Empty means "all txs were executed"
    /// (backwards-compatible default for verification mode).
    pub executed_tx_indices: Option<Vec<usize>>,
    /// Indices of input EVM txs that block building found invalid on their own.
    ///
    /// These do not decode or fail a check that waiting cannot cure, unlike a
    /// tx deferred by the block gas budget or one whose nonce is still ahead
    /// of its account. The proposer drops them from its pending pool so they
    /// cannot occupy every later proposal.
    pub rejected_tx_indices: Vec<usize>,
}

impl ExecutionOutcome {
    /// Create a new empty execution outcome.
    #[must_use]
    pub fn new() -> Self {
        Self {
            changes: ChangeSet::new(),
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
        assert!(outcome.changes.is_empty());
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.gas_used, 0);
    }
}
