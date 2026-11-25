//! The genesis block of a chain whose partitions hold the genesis state.

use alloy_primitives::B256;
use vera_domain::{Block, BlockId, DbTarget};

/// The genesis block committing to the partitions' genesis targets.
pub fn genesis_block(
    module_state_root: B256,
    native_targets: [DbTarget; 4],
    receipt_commitment: B256,
) -> Block {
    Block {
        context: Block::genesis_context(),
        parent: BlockId(B256::ZERO),
        height: 0,
        ancestry: vera_domain::Ancestry::genesis(),
        timestamp: 0,
        term: 0,
        module_state_root,
        txs: Vec::new(),
        payload: None,
        native_targets,
        receipt_commitment,
    }
}
