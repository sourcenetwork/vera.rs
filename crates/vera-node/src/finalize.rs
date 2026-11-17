//! Finalized-block indexing and RPC subscription data construction.

use std::collections::HashMap;

use alloy_consensus::{Transaction as _, TxEnvelope, transaction::SignerRecoverable as _};
use alloy_eips::eip2718::Decodable2718 as _;
use alloy_primitives::{Address, B256, U256, keccak256};
use tracing::{error, trace, warn};
use vera_crypto::bls;
use vera_domain::{Block, NativeTx};
use vera_executor::ExecutionReceipt;
use vera_indexer::{BlockIndex, IndexedBlock, IndexedLog, IndexedReceipt, IndexedTransaction};
use vera_jsonrpc::{BlockTransactions, RpcBlock, RpcLog};

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
    // Build a lookup map from tx_hash → receipt. Receipts are ordered by
    // execution order (natives first, then EVMs), not by block tx position.
    let receipt_map: HashMap<B256, &ExecutionReceipt> =
        receipts.iter().map(|r| (r.tx_hash, r)).collect();

    let mut tx_hashes = Vec::with_capacity(block.txs.len());
    let mut indexed_txs = Vec::with_capacity(block.txs.len());
    let mut indexed_receipts = Vec::with_capacity(receipts.len());
    let mut block_log_index: u64 = 0;

    for (i, tx) in block.txs.iter().enumerate() {
        let is_native = !tx.bytes.is_empty() && NativeTx::is_native_tx(tx.bytes[0]);

        let (tx_hash, sender, to, value, tx_gas_limit, gas_price, input, nonce, signer_did) =
            if is_native {
                match NativeTx::decode_wire(&tx.bytes) {
                    Ok(native_tx) => {
                        let did =
                            bls::did_from_compressed_pubkey(native_tx.bls_pubkey.as_slice()).ok();
                        (
                            native_tx.tx_id().0,
                            Address::ZERO,
                            Some(native_tx.target),
                            U256::ZERO,
                            0u64,
                            0u128,
                            native_tx.calldata,
                            native_tx.nonce,
                            did,
                        )
                    }
                    Err(e) => {
                        let fallback_hash = keccak256(&tx.bytes);
                        error!(height = block.height, index = i, %fallback_hash, error = %e, "failed to decode native tx for indexing");
                        tx_hashes.push(fallback_hash);
                        continue;
                    }
                }
            } else {
                let evm_hash = keccak256(&tx.bytes);
                let Ok(envelope) = TxEnvelope::decode_2718(&mut tx.bytes.as_ref()) else {
                    error!(height = block.height, index = i, %evm_hash, "failed to decode tx for indexing");
                    tx_hashes.push(evm_hash);
                    continue;
                };
                let Ok(sender) = envelope.recover_signer() else {
                    error!(height = block.height, index = i, %evm_hash, "failed to recover sender for indexing");
                    tx_hashes.push(evm_hash);
                    continue;
                };
                (
                    evm_hash,
                    sender,
                    envelope.to(),
                    envelope.value(),
                    envelope.gas_limit(),
                    envelope
                        .gas_price()
                        .unwrap_or_else(|| envelope.max_fee_per_gas()),
                    envelope.input().clone(),
                    envelope.nonce(),
                    None,
                )
            };

        tx_hashes.push(tx_hash);

        indexed_txs.push(IndexedTransaction {
            hash: tx_hash,
            block_hash,
            block_number: block.height,
            transaction_index: i as u64,
            from: sender,
            to,
            value,
            gas_limit: tx_gas_limit,
            gas_price,
            input,
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
                from: sender,
                to,
                cumulative_gas_used: receipt.cumulative_gas_used(),
                gas_used: receipt.gas_used,
                contract_address: receipt.contract_address,
                logs,
                status: receipt.success(),
                signer_did,
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
        state_root: block.state_root.0,
        module_state_root: block.module_state_root,
        timestamp: block.timestamp,
        gas_limit,
        gas_used,
        base_fee_per_gas: Some(0),
        prevrandao: block.prevrandao,
        transaction_hashes: tx_hashes.clone(),
    };

    index.insert_block(indexed_block, indexed_txs, indexed_receipts);
    trace!(height = block.height, "indexed finalized block");
    tx_hashes
}

/// Build RPC subscription data from a finalized block and its receipts.
///
/// `tx_hashes` are the block's transaction hashes in block order, as returned
/// by [`index_finalized_block`].
pub fn subscription_data(
    block: &Block,
    block_hash: B256,
    gas_limit: u64,
    receipts: &[ExecutionReceipt],
    gas_used: u64,
    tx_hashes: &[B256],
) -> (RpcBlock, Vec<RpcLog>) {
    use alloy_primitives::{Bytes, U64};

    let rpc_block = RpcBlock {
        hash: block_hash,
        parent_hash: block.parent.0,
        number: U64::from(block.height),
        state_root: block.state_root.0,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Bytes::new(),
        timestamp: U64::from(block.timestamp),
        gas_limit: U64::from(gas_limit),
        gas_used: U64::from(gas_used),
        extra_data: Bytes::new(),
        mix_hash: block.prevrandao,
        nonce: Default::default(),
        base_fee_per_gas: Some(U256::ZERO),
        miner: Address::ZERO,
        difficulty: U256::ZERO,
        total_difficulty: U256::ZERO,
        uncles: vec![],
        size: U64::ZERO,
        transactions: BlockTransactions::Hashes(tx_hashes.to_vec()),
    };

    let receipt_map: HashMap<B256, &ExecutionReceipt> =
        receipts.iter().map(|r| (r.tx_hash, r)).collect();

    let mut rpc_logs = Vec::new();
    let mut block_log_index: u64 = 0;
    for (i, &tx_hash) in tx_hashes.iter().enumerate() {
        if let Some(receipt) = receipt_map.get(&tx_hash) {
            for log in receipt.logs() {
                let idx = block_log_index;
                block_log_index += 1;
                rpc_logs.push(RpcLog {
                    address: log.address,
                    topics: log.data.topics().to_vec(),
                    data: log.data.data.clone(),
                    block_number: U64::from(block.height),
                    transaction_hash: tx_hash,
                    transaction_index: U64::from(i as u64),
                    block_hash,
                    log_index: U64::from(idx),
                    removed: false,
                });
            }
        } else {
            warn!(
                height = block.height,
                tx_index = i,
                "missing receipt for transaction in subscription data"
            );
        }
    }

    (rpc_block, rpc_logs)
}

#[cfg(test)]
#[path = "finalize_tests.rs"]
mod tests;
