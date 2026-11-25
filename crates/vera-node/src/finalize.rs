//! Finalized-block indexing for the RPC query index.

use std::collections::HashMap;

use alloy_primitives::{B256, keccak256};
use tracing::{error, trace, warn};
use vera_crypto::bls;
use vera_domain::{Block, NativeTx};
use vera_executor::ExecutionReceipt;
use vera_indexer::{BlockIndex, IndexedBlock, IndexedLog, IndexedReceipt, IndexedTransaction};

/// Index a finalized block into the block index.
///
/// `block_hash` is the block's identifier, which the caller computes once per
/// finalized block: deriving it re-encodes and hashes the whole block.
/// Returns the hash of each transaction in block order, as indexed.
pub fn index_finalized_block(
    index: &BlockIndex,
    block: &Block,
    block_hash: B256,
    gas_limit: u64,
    receipts: &[ExecutionReceipt],
    gas_used: u64,
) -> Vec<B256> {
    // Receipts are looked up by request identifier, not by block position.
    let receipt_map: HashMap<B256, &ExecutionReceipt> =
        receipts.iter().map(|r| (r.tx_hash, r)).collect();

    let mut tx_hashes = Vec::with_capacity(block.txs.len());
    let mut indexed_txs = Vec::with_capacity(block.txs.len());
    let mut indexed_receipts = Vec::with_capacity(receipts.len());
    let mut block_log_index: u64 = 0;

    for (i, tx) in block.txs.iter().enumerate() {
        let decoded = NativeTx::decode_wire(&tx.bytes)
            .map_err(|error| error.to_string())
            .and_then(|native_tx| {
                bls::did_from_compressed_pubkey(native_tx.bls_pubkey.as_slice())
                    .map(|did| (native_tx, did))
                    .map_err(|error| error.to_string())
            });
        let (native_tx, signer_did) = match decoded {
            Ok(decoded) => decoded,
            Err(error) => {
                let fallback_hash = keccak256(&tx.bytes);
                error!(height = block.height, index = i, %fallback_hash, %error, "failed to decode native tx for indexing");
                tx_hashes.push(fallback_hash);
                continue;
            }
        };
        let tx_hash = native_tx.tx_id().0;
        let (target, nonce) = (native_tx.target, native_tx.nonce);

        tx_hashes.push(tx_hash);

        indexed_txs.push(IndexedTransaction {
            hash: tx_hash,
            block_hash,
            block_number: block.height,
            transaction_index: i as u64,
            target,
            input: native_tx.calldata,
            nonce,
            signer_did: signer_did.clone(),
        });

        if let Some(receipt) = receipt_map.get(&tx_hash) {
            let logs = receipt
                .logs()
                .iter()
                .map(|log| {
                    let idx = block_log_index;
                    block_log_index += 1;
                    IndexedLog {
                        address: log.address,
                        topics: log.data.topics().to_vec(),
                        data: log.data.data.clone(),
                        log_index: idx,
                        block_hash,
                        block_number: block.height,
                        transaction_hash: tx_hash,
                        transaction_index: i as u64,
                    }
                })
                .collect();

            indexed_receipts.push(IndexedReceipt {
                transaction_hash: tx_hash,
                block_hash,
                block_number: block.height,
                transaction_index: i as u64,
                target,
                signer_did,
                nonce,
                cumulative_gas_used: receipt.cumulative_gas_used(),
                gas_used: receipt.gas_used,
                logs,
                status: receipt.success(),
                refusal: receipt.refusal.clone(),
            });
        } else {
            warn!(
                height = block.height,
                tx_index = i,
                %tx_hash,
                "missing receipt for transaction"
            );
        }
    }

    let indexed_block = IndexedBlock {
        hash: block_hash,
        number: block.height,
        parent_hash: block.parent.0,
        module_state_root: block.module_state_root,
        timestamp: block.timestamp,
        gas_limit,
        gas_used,
        transaction_hashes: tx_hashes.clone(),
    };

    index.insert_block(indexed_block, indexed_txs, indexed_receipts);
    trace!(height = block.height, "indexed finalized block");
    tx_hashes
}

#[cfg(test)]
#[path = "finalize_tests.rs"]
mod tests;
