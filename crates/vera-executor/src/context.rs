//! Block execution context.

use alloy_consensus::Header;
use alloy_primitives::B256;

/// Context for block execution.
///
/// Contains the block header and additional execution parameters.
#[derive(Clone, Debug)]
pub struct BlockContext {
    /// Block header.
    pub header: Header,
    /// Parent block hash.
    pub parent_hash: B256,
    /// Previous block's randomness (prevrandao).
    pub prevrandao: B256,
    /// True when re-executing a block for verification or finalization
    /// (as opposed to building a new proposal). Executors use this to
    /// decide whether speculative module state should be
    /// overwritten on re-execution at the same height.
    pub is_verification: bool,
    /// Module state root of the block being verified. Ordered storage compares
    /// it with the root of its authenticated partitions; the executor does not.
    pub expected_module_state_root: Option<B256>,
}

impl BlockContext {
    /// Create a new block context.
    #[must_use]
    pub const fn new(header: Header, parent_hash: B256, prevrandao: B256) -> Self {
        Self {
            header,
            parent_hash,
            prevrandao,
            is_verification: false,
            expected_module_state_root: None,
        }
    }

    /// Mark this context as a verification execution.
    #[must_use]
    pub const fn with_verification(mut self) -> Self {
        self.is_verification = true;
        self
    }

    /// Set the expected module state root for verification.
    #[must_use]
    pub const fn with_expected_module_state_root(mut self, root: B256) -> Self {
        self.expected_module_state_root = Some(root);
        self
    }

    /// Get the base fee from the header.
    pub fn base_fee(&self) -> u64 {
        self.header.base_fee_per_gas.unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_context_new() {
        let header = Header::default();
        let parent_hash = B256::repeat_byte(1);
        let prevrandao = B256::ZERO;
        let context = BlockContext::new(header, parent_hash, prevrandao);
        assert_eq!(context.prevrandao, B256::ZERO);
        assert_eq!(context.parent_hash, parent_hash);
    }
}
