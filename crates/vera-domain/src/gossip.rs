//! Gossip header type for finalized block header propagation.

use alloy_evm::revm::primitives::B256;
use serde::{Deserialize, Serialize};

use crate::Block;

/// Finalized block header published to header subscribers.
///
/// Validators publish one of these for each finalized block. Subscribers use
/// `chain_id` + sequential `height` + `parent_hash` to follow the header
/// chain. Native module proofs verify against `module_state_root`.
///
/// Nothing here signs the header's own fields: `signature` carries the
/// finalization certificate for the block's consensus proposal, which a
/// consumer checks against its configured finality trust together with the
/// block it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipHeader {
    /// Chain ID (for replay protection).
    pub chain_id: u64,
    /// Finalized block height.
    pub height: u64,
    /// Block hash.
    pub block_hash: B256,
    /// Parent block hash (for chain continuity verification).
    pub parent_hash: B256,
    /// Block timestamp (Unix seconds).
    pub timestamp: u64,
    /// Term of the device that proposed the block.
    pub term: u64,
    /// Combined current-QMDB root for ACP, bulletin, Vera and native sequences.
    pub module_state_root: B256,
    /// Number of transactions in the block.
    pub tx_count: u32,
    /// Validator index that published this header.
    pub publisher_index: u32,
    /// Encoded finalization certificate for the block's proposal; empty until attached.
    pub signature: Vec<u8>,
}

impl GossipHeader {
    /// Construct from a finalized block (without a certificate — call `set_signature` after).
    pub fn from_block(block: &Block, chain_id: u64, publisher_index: u32) -> Self {
        Self::from_block_with_hash(block, block.id().0, chain_id, publisher_index)
    }

    /// As [`Self::from_block`], for a caller that already computed the block's hash.
    pub const fn from_block_with_hash(
        block: &Block,
        block_hash: B256,
        chain_id: u64,
        publisher_index: u32,
    ) -> Self {
        Self {
            chain_id,
            height: block.height,
            block_hash,
            parent_hash: block.parent.0,
            timestamp: block.timestamp,
            term: block.term,
            module_state_root: block.module_state_root,
            tx_count: block.txs.len() as u32,
            publisher_index,
            signature: Vec::new(),
        }
    }

    /// Attach the encoded finalization certificate.
    pub fn set_signature(&mut self, sig: &[u8]) {
        self.signature = sig.to_vec();
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;

    use super::*;
    use crate::{BlockId, Tx};

    fn sample_block() -> Block {
        Block {
            context: Block::genesis_context(),
            parent: BlockId(B256::repeat_byte(0x01)),
            height: 42,
            timestamp: 1_700_000_000,
            term: 3,
            module_state_root: B256::repeat_byte(0xef),
            txs: vec![Tx::new(Bytes::from_static(&[0xde, 0xad]))],
            payload: None,
            native_targets: Default::default(),
            receipt_commitment: alloy_primitives::B256::ZERO,
        }
    }

    #[test]
    fn from_block_populates_fields() {
        let block = sample_block();
        let header = GossipHeader::from_block(&block, 1337, 2);

        assert_eq!(header.chain_id, 1337);
        assert_eq!(header.height, 42);
        assert_eq!(header.block_hash, block.id().0);
        assert_eq!(header.parent_hash, B256::repeat_byte(0x01));
        assert_eq!(header.timestamp, 1_700_000_000);
        assert_eq!(header.term, 3);
        assert_eq!(header.module_state_root, B256::repeat_byte(0xef));
        assert_eq!(header.tx_count, 1);
        assert_eq!(header.publisher_index, 2);
        assert!(header.signature.is_empty());
    }

    #[test]
    fn serde_json_roundtrip() {
        let block = sample_block();
        let mut header = GossipHeader::from_block(&block, 1337, 0);
        header.set_signature(&[0xBB; 64]);
        let json = serde_json::to_string(&header).expect("serialize");
        let parsed: GossipHeader = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(header, parsed);
    }
}
