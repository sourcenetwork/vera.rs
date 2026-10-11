//! Gossip header type for finalized block header propagation.

use alloy_evm::revm::primitives::{B256, keccak256};
use serde::{Deserialize, Serialize};

use crate::Block;

/// BLS threshold finalization certificate length (bytes).
const SIGNATURE_LEN: usize = 96;

/// Wire format size of a gossip header (bytes).
///
/// Layout: 8 + 8 + 32 + 32 + 8 + 32 + 32 + 4 + 4 + 96 = 256
pub const GOSSIP_HEADER_SIZE: usize = 160 + SIGNATURE_LEN;

/// Signed finalized block header published to gossip subscribers.
///
/// Validators publish one of these for each finalized block. Subscribers use
/// `chain_id` + sequential `height` + `parent_hash` to build a verified header
/// chain. Native module proofs verify against `module_state_root`.
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
    /// EVM state root (QMDB).
    pub state_root: B256,
    /// Combined current-QMDB root for ACP, bulletin, Vera and native sequences.
    pub module_state_root: B256,
    /// Number of transactions in the block.
    pub tx_count: u32,
    /// Validator index that published this header.
    pub publisher_index: u32,
    /// BLS threshold finalization certificate (96 bytes when finalized, empty before then).
    pub signature: Vec<u8>,
}

impl GossipHeader {
    /// Construct from a finalized block (without a certificate — call `set_signature` after).
    pub fn from_block(block: &Block, chain_id: u64, publisher_index: u32) -> Self {
        Self {
            chain_id,
            height: block.height,
            block_hash: block.id().0,
            parent_hash: block.parent.0,
            timestamp: block.timestamp,
            state_root: block.state_root.0,
            module_state_root: block.module_state_root,
            tx_count: block.txs.len() as u32,
            publisher_index,
            signature: Vec::new(),
        }
    }

    /// Content identifier for dedup — `keccak256` over the block-identifying fields.
    ///
    /// This is the same for all validators publishing the same finalized block
    /// (excludes `publisher_index` and `signature`). Consumers dedup on this.
    #[must_use]
    pub fn content_id(&self) -> B256 {
        let mut data = Vec::with_capacity(152);
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(self.block_hash.as_slice());
        data.extend_from_slice(self.parent_hash.as_slice());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(self.state_root.as_slice());
        data.extend_from_slice(self.module_state_root.as_slice());
        data.extend_from_slice(&self.tx_count.to_le_bytes());
        keccak256(&data)
    }

    /// Deterministic bytes for signing (all fields except signature).
    #[must_use]
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(self.block_hash.as_slice());
        data.extend_from_slice(self.parent_hash.as_slice());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(self.state_root.as_slice());
        data.extend_from_slice(self.module_state_root.as_slice());
        data.extend_from_slice(&self.tx_count.to_le_bytes());
        data.extend_from_slice(&self.publisher_index.to_le_bytes());
        data
    }

    /// Set the BLS threshold finalization certificate bytes (exactly 96 bytes).
    pub fn set_signature(&mut self, sig: &[u8]) {
        self.signature = sig.to_vec();
    }

    /// Encode the complete header (including signature) to wire format.
    #[must_use]
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut data = self.signing_data();
        let mut sig_padded = [0u8; SIGNATURE_LEN];
        let copy_len = self.signature.len().min(SIGNATURE_LEN);
        sig_padded[..copy_len].copy_from_slice(&self.signature[..copy_len]);
        data.extend_from_slice(&sig_padded);
        data
    }

    /// Decode a header from wire format bytes.
    #[must_use]
    pub fn decode_wire(data: &[u8]) -> Option<Self> {
        if data.len() != GOSSIP_HEADER_SIZE {
            return None;
        }
        let mut off = 0;

        let chain_id = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
        off += 8;
        let height = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
        off += 8;
        let block_hash = B256::from_slice(&data[off..off + 32]);
        off += 32;
        let parent_hash = B256::from_slice(&data[off..off + 32]);
        off += 32;
        let timestamp = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
        off += 8;
        let state_root = B256::from_slice(&data[off..off + 32]);
        off += 32;
        let module_state_root = B256::from_slice(&data[off..off + 32]);
        off += 32;
        let tx_count = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        off += 4;
        let publisher_index = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        off += 4;
        let signature = data[off..off + SIGNATURE_LEN].to_vec();

        Some(Self {
            chain_id,
            height,
            block_hash,
            parent_hash,
            timestamp,
            state_root,
            module_state_root,
            tx_count,
            publisher_index,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;

    use super::*;
    use crate::{BlockId, StateRoot, Tx};

    fn sample_block() -> Block {
        Block {
            context: Block::genesis_context(),
            parent: BlockId(B256::repeat_byte(0x01)),
            height: 42,
            timestamp: 1_700_000_000,
            prevrandao: B256::repeat_byte(0xab),
            state_root: StateRoot(B256::repeat_byte(0xcd)),
            module_state_root: B256::repeat_byte(0xef),
            txs: vec![Tx::new(Bytes::from_static(&[0xde, 0xad]))],
            payload: None,
            native_targets: None,
            receipt_commitment: None,
            db_targets: crate::DbTargets::default(),
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
        assert_eq!(header.state_root, B256::repeat_byte(0xcd));
        assert_eq!(header.module_state_root, B256::repeat_byte(0xef));
        assert_eq!(header.tx_count, 1);
        assert_eq!(header.publisher_index, 2);
        assert!(header.signature.is_empty());
    }

    #[test]
    fn signing_data_is_deterministic() {
        let block = sample_block();
        let header = GossipHeader::from_block(&block, 1337, 0);
        assert_eq!(header.signing_data(), header.signing_data());
    }

    #[test]
    fn signing_data_excludes_signature() {
        let block = sample_block();
        let mut header = GossipHeader::from_block(&block, 1337, 0);
        let data1 = header.signing_data();
        header.set_signature(&[0xFF; 96]);
        let data2 = header.signing_data();
        assert_eq!(data1, data2);
    }

    #[test]
    fn signing_data_length() {
        let block = sample_block();
        let header = GossipHeader::from_block(&block, 1337, 0);
        assert_eq!(header.signing_data().len(), 160);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let block = sample_block();
        let mut header = GossipHeader::from_block(&block, 1337, 2);
        header.set_signature(&[0xAA; 96]);

        let encoded = header.encode_wire();
        assert_eq!(encoded.len(), GOSSIP_HEADER_SIZE);

        let decoded = GossipHeader::decode_wire(&encoded).expect("decode should succeed");
        assert_eq!(header, decoded);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(GossipHeader::decode_wire(&[0u8; 10]).is_none());
        assert!(GossipHeader::decode_wire(&[0u8; GOSSIP_HEADER_SIZE + 1]).is_none());
    }

    #[test]
    fn content_id_same_for_different_publishers() {
        let block = sample_block();
        let h1 = GossipHeader::from_block(&block, 1337, 0);
        let h2 = GossipHeader::from_block(&block, 1337, 3);
        assert_eq!(h1.content_id(), h2.content_id());
    }

    #[test]
    fn content_id_differs_for_different_blocks() {
        let block = sample_block();
        let h1 = GossipHeader::from_block(&block, 1337, 0);
        let mut block2 = sample_block();
        block2.height = 99;
        let h2 = GossipHeader::from_block(&block2, 1337, 0);
        assert_ne!(h1.content_id(), h2.content_id());
    }

    #[test]
    fn different_chain_id_produces_different_signing_data() {
        let block = sample_block();
        let h1 = GossipHeader::from_block(&block, 1, 0);
        let h2 = GossipHeader::from_block(&block, 2, 0);
        assert_ne!(h1.signing_data(), h2.signing_data());
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
