//! Block execution context.

use alloy_primitives::B256;

/// The block a set of requests executes in.
#[derive(Clone, Debug)]
pub struct BlockContext {
    /// Height of the block.
    pub height: u64,
    /// Block time in Unix seconds.
    pub timestamp: u64,
    /// Gas the block's requests may use in total.
    pub gas_limit: u64,
    /// True when re-executing a block for verification or finalization, as
    /// opposed to building a proposal. Building skips requests that cannot
    /// run; verification rejects the block.
    pub is_verification: bool,
    /// Module state root of the block being verified. Ordered storage compares
    /// it with the root of its authenticated partitions; the executor does not.
    pub expected_module_state_root: Option<B256>,
}

impl BlockContext {
    /// The context of a block being built.
    #[must_use]
    pub const fn new(height: u64, timestamp: u64, gas_limit: u64) -> Self {
        Self {
            height,
            timestamp,
            gas_limit,
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
}
