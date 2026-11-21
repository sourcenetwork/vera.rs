//! Indexed types for revisions, requests, receipts, and logs.

use alloy_primitives::{Address, B256, Bytes};

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

/// An indexed revision header with the identifiers of its requests.
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
    /// Execution gas limit of this block.
    pub gas_limit: u64,
    /// Gas used by all requests in this block.
    pub gas_used: u64,
    /// Identifiers of the requests included in this block.
    pub transaction_hashes: Vec<B256>,
}

/// An indexed native request.
#[derive(Debug, Clone)]
pub struct IndexedTransaction {
    /// Request identifier.
    pub hash: B256,
    /// Hash of the block containing this request.
    pub block_hash: B256,
    /// Number of the block containing this request.
    pub block_number: u64,
    /// Index of the request within the block.
    pub transaction_index: u64,
    /// Module address the request calls.
    pub target: Address,
    /// ABI-encoded module call.
    pub input: Bytes,
    /// The signer's sequence.
    pub nonce: u64,
    /// DID of the BLS signer.
    pub signer_did: String,
}

/// An indexed execution result of a native request.
#[derive(Debug, Clone)]
pub struct IndexedReceipt {
    /// Request identifier.
    pub transaction_hash: B256,
    /// Hash of the block containing this request.
    pub block_hash: B256,
    /// Number of the block containing this request.
    pub block_number: u64,
    /// Index of the request within the block.
    pub transaction_index: u64,
    /// Module address the request called.
    pub target: Address,
    /// DID of the BLS signer.
    pub signer_did: String,
    /// The signer's sequence.
    pub nonce: u64,
    /// Cumulative gas used in the block up to and including this request.
    pub cumulative_gas_used: u64,
    /// Gas used by this request.
    pub gas_used: u64,
    /// Logs emitted by this request.
    pub logs: Vec<IndexedLog>,
    /// Whether the module call ran to completion.
    pub status: bool,
    /// Why a module refused the request; `None` on success.
    pub refusal: Option<vera_domain::Refusal>,
}

/// An indexed log entry.
#[derive(Debug, Clone)]
pub struct IndexedLog {
    /// Address of the module that emitted the log.
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
