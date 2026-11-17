//! Indexed types for blocks, transactions, receipts, and logs.

use alloy_primitives::{Address, B256, Bytes, U256};

/// A point lookup into retained execution history.
#[derive(Debug, Clone, Copy)]
pub enum IndexQuery {
    /// Revision number.
    Revision(u64),
    /// Canonical revision hash.
    RevisionHash(B256),
    /// Submission identifier.
    Submission(B256),
}

/// An indexed block containing header information and transaction hashes.
#[derive(Debug, Clone)]
pub struct IndexedBlock {
    /// Block hash.
    pub hash: B256,
    /// Block number.
    pub number: u64,
    /// Parent block hash.
    pub parent_hash: B256,
    /// State root after executing this block.
    pub state_root: B256,
    /// Combined root of per-module state trees (ACP, Bulletin, Vera, NativeNonce).
    pub module_state_root: B256,
    /// Block timestamp.
    pub timestamp: u64,
    /// Gas limit for this block.
    pub gas_limit: u64,
    /// Gas used by all transactions in this block.
    pub gas_used: u64,
    /// Base fee per gas (EIP-1559).
    pub base_fee_per_gas: Option<u64>,
    /// Randomness beacon value (prevrandao / mix_hash).
    pub prevrandao: B256,
    /// Hashes of transactions included in this block.
    pub transaction_hashes: Vec<B256>,
}

/// An indexed transaction with full details.
#[derive(Debug, Clone)]
pub struct IndexedTransaction {
    /// Transaction hash.
    pub hash: B256,
    /// Hash of the block containing this transaction.
    pub block_hash: B256,
    /// Number of the block containing this transaction.
    pub block_number: u64,
    /// Index of the transaction within the block.
    pub transaction_index: u64,
    /// Sender address.
    pub from: Address,
    /// Recipient address (None for contract creation).
    pub to: Option<Address>,
    /// Value transferred.
    pub value: U256,
    /// Gas limit for this transaction.
    pub gas_limit: u64,
    /// Gas price.
    pub gas_price: u128,
    /// Input data.
    pub input: Bytes,
    /// Sender nonce.
    pub nonce: u64,
    /// DID of the BLS signer (`None` for EVM transactions).
    pub signer_did: Option<String>,
}

/// An indexed transaction receipt.
#[derive(Debug, Clone)]
pub struct IndexedReceipt {
    /// Transaction hash.
    pub transaction_hash: B256,
    /// Hash of the block containing this transaction.
    pub block_hash: B256,
    /// Number of the block containing this transaction.
    pub block_number: u64,
    /// Index of the transaction within the block.
    pub transaction_index: u64,
    /// Sender address.
    pub from: Address,
    /// Recipient address (None for contract creation).
    pub to: Option<Address>,
    /// Cumulative gas used in the block up to and including this transaction.
    pub cumulative_gas_used: u64,
    /// Gas used by this transaction.
    pub gas_used: u64,
    /// Contract address created (if contract creation transaction).
    pub contract_address: Option<Address>,
    /// Logs emitted by this transaction.
    pub logs: Vec<IndexedLog>,
    /// Transaction status (true = success, false = revert).
    pub status: bool,
    /// DID of the BLS signer (`None` for EVM transactions).
    pub signer_did: Option<String>,
    /// Why a module refused a native request (`None` on success and for EVM transactions).
    pub refusal: Option<vera_domain::Refusal>,
}

/// An indexed log entry.
#[derive(Debug, Clone)]
pub struct IndexedLog {
    /// Address of the contract that emitted the log.
    pub address: Address,
    /// Indexed topics.
    pub topics: Vec<B256>,
    /// Non-indexed data.
    pub data: Bytes,
    /// Log index within the block.
    pub log_index: u64,
    /// Hash of the block containing this log.
    pub block_hash: B256,
    /// Number of the block containing this log.
    pub block_number: u64,
    /// Hash of the transaction that emitted this log.
    pub transaction_hash: B256,
    /// Index of the transaction within the block.
    pub transaction_index: u64,
}

/// Statistics about the block index.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexStats {
    /// Accounted resident revision bytes, excluding map overhead and evicted reader snapshots.
    pub cached_bytes: usize,
    /// Total number of indexed blocks.
    pub block_count: usize,
    /// Total number of indexed transactions.
    pub transaction_count: usize,
    /// Total number of indexed receipts.
    pub receipt_count: usize,
    /// Current head block number.
    pub head_block_number: u64,
}
