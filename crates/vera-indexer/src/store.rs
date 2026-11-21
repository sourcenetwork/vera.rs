//! Bounded in-memory indexes over finalized revisions.

use crate::{
    IndexStats, IndexedBlock, IndexedLog, IndexedReceipt, IndexedTransaction, IndexerError,
    LogFilter, LogQuery,
};
use alloy_primitives::B256;
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tracing::debug;

/// Maximum number of resident finalized revisions.
pub const MAX_CACHED_REVISIONS: usize = 1_024;
const MAX_CACHED_BYTES: usize = 64 << 20;

/// An immutable revision retained by readers independently of cache eviction.
#[derive(Debug, Clone)]
pub struct IndexedRevision {
    /// Revision header and submission order.
    pub block: IndexedBlock,
    /// Indexed submissions.
    pub transactions: Vec<IndexedTransaction>,
    /// Indexed execution results.
    pub receipts: Vec<IndexedReceipt>,
    bytes: usize,
}

#[derive(Debug, Default)]
struct Cache {
    revisions: HashMap<B256, Arc<IndexedRevision>>,
    numbers: BTreeMap<u64, B256>,
    transactions: HashMap<B256, (B256, usize)>,
    receipts: HashMap<B256, (B256, usize)>,
    bytes: usize,
}

impl Cache {
    fn remove(&mut self, hash: B256) {
        let Some(revision) = self.revisions.remove(&hash) else {
            return;
        };
        self.numbers.remove(&revision.block.number);
        self.bytes -= revision.bytes;
        for tx in &revision.transactions {
            if self
                .transactions
                .get(&tx.hash)
                .is_some_and(|(owner, _)| *owner == hash)
            {
                self.transactions.remove(&tx.hash);
            }
        }
        for receipt in &revision.receipts {
            if self
                .receipts
                .get(&receipt.transaction_hash)
                .is_some_and(|(owner, _)| *owner == hash)
            {
                self.receipts.remove(&receipt.transaction_hash);
            }
        }
    }
}

/// Recent execution cache. The newest revision stays resident even when its
/// payload alone exceeds the byte budget; older data is served from history.
#[derive(Debug, Default)]
pub struct BlockIndex {
    cache: RwLock<Cache>,
}

impl BlockIndex {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically publish a complete revision and evict the oldest entries.
    pub fn insert_block(
        &self,
        block: IndexedBlock,
        txs: Vec<IndexedTransaction>,
        receipts: Vec<IndexedReceipt>,
    ) {
        let mut revision = IndexedRevision {
            block,
            transactions: txs,
            receipts,
            bytes: 0,
        };
        revision.bytes = revision.retained_bytes();
        let hash = revision.block.hash;
        let number = revision.block.number;
        debug!(number, %hash, txs = revision.transactions.len(), "indexing revision");
        let mut cache = self.cache.write();
        if let Some(previous) = cache.numbers.get(&number).copied() {
            cache.remove(previous);
        }
        cache.remove(hash);
        for (position, tx) in revision.transactions.iter().enumerate() {
            cache.transactions.insert(tx.hash, (hash, position));
        }
        for (position, receipt) in revision.receipts.iter().enumerate() {
            cache
                .receipts
                .insert(receipt.transaction_hash, (hash, position));
        }
        cache.bytes += revision.bytes;
        cache.numbers.insert(number, hash);
        cache.revisions.insert(hash, Arc::new(revision));
        while cache.revisions.len() > 1
            && (cache.revisions.len() > MAX_CACHED_REVISIONS || cache.bytes > MAX_CACHED_BYTES)
        {
            let oldest = *cache.numbers.first_key_value().expect("nonempty cache").1;
            cache.remove(oldest);
        }
    }

    /// Gets a block by hash.
    pub fn get_block_by_hash(&self, hash: &B256) -> Option<IndexedBlock> {
        Some(self.cache.read().revisions.get(hash)?.block.clone())
    }

    /// Gets a block by number.
    pub fn get_block_by_number(&self, number: u64) -> Option<IndexedBlock> {
        let cache = self.cache.read();
        Some(
            cache
                .revisions
                .get(cache.numbers.get(&number)?)?
                .block
                .clone(),
        )
    }

    /// Capture the current header without a separate head-number lookup.
    pub fn latest_block(&self) -> Option<IndexedBlock> {
        let cache = self.cache.read();
        Some(
            cache
                .revisions
                .get(cache.numbers.last_key_value()?.1)?
                .block
                .clone(),
        )
    }

    /// Gets a transaction by hash.
    pub fn get_transaction(&self, hash: &B256) -> Option<IndexedTransaction> {
        let cache = self.cache.read();
        let (revision, position) = cache.transactions.get(hash)?;
        Some(cache.revisions.get(revision)?.transactions[*position].clone())
    }

    /// Gets a receipt by submission hash.
    pub fn get_receipt(&self, hash: &B256) -> Option<IndexedReceipt> {
        let cache = self.cache.read();
        let (revision, position) = cache.receipts.get(hash)?;
        Some(cache.revisions.get(revision)?.receipts[*position].clone())
    }

    /// Capture a receipt and its submission metadata under the same cache lock.
    pub fn receipt_with_transaction(
        &self,
        hash: &B256,
    ) -> Option<(IndexedReceipt, Option<IndexedTransaction>)> {
        let cache = self.cache.read();
        let (owner, position) = cache.receipts.get(hash)?;
        let revision = cache.revisions.get(owner)?;
        let receipt = revision.receipts[*position].clone();
        let tx = cache
            .transactions
            .get(hash)
            .and_then(|(tx_owner, position)| {
                (*tx_owner == *owner).then(|| revision.transactions[*position].clone())
            });
        Some((receipt, tx))
    }

    /// Retain complete execution data across asynchronous proof assembly.
    pub fn receipt_revision(&self, hash: &B256) -> Option<Arc<IndexedRevision>> {
        let cache = self.cache.read();
        let (revision, _) = cache.receipts.get(hash)?;
        cache.revisions.get(revision).cloned()
    }

    /// Returns the current head number.
    #[must_use]
    pub fn head_block_number(&self) -> u64 {
        self.cache
            .read()
            .numbers
            .last_key_value()
            .map_or(0, |(number, _)| *number)
    }

    /// Query resident logs with aggregate scan/result limits.
    pub fn get_logs(&self, filter: &LogFilter) -> Result<Vec<IndexedLog>, IndexerError> {
        let mut query = LogQuery::new(filter.clone(), self.head_block_number())?;
        for height in query.from..=query.to {
            self.collect_revision_logs(height, &mut query)?;
        }
        Ok(query.finish())
    }

    /// Collect a resident revision, returning false when history is needed.
    pub fn collect_revision_logs(
        &self,
        height: u64,
        query: &mut LogQuery,
    ) -> Result<bool, IndexerError> {
        let revision = {
            let cache = self.cache.read();
            let Some(hash) = cache.numbers.get(&height) else {
                return Ok(false);
            };
            cache.revisions.get(hash).expect("indexed revision").clone()
        };
        for log in revision.receipts.iter().flat_map(|receipt| &receipt.logs) {
            query.push(log)?;
        }
        Ok(true)
    }

    /// Number of resident revisions.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.cache.read().revisions.len()
    }
    /// Whether the cache has no revisions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.read().revisions.is_empty()
    }
    /// Coherent resident counts, accounted bytes and head number.
    #[must_use]
    pub fn stats(&self) -> IndexStats {
        let cache = self.cache.read();
        IndexStats {
            cached_bytes: cache.bytes,
            block_count: cache.revisions.len(),
            transaction_count: cache.transactions.len(),
            receipt_count: cache.receipts.len(),
            head_block_number: cache.numbers.last_key_value().map_or(0, |(n, _)| *n),
        }
    }
}

impl IndexedRevision {
    fn retained_bytes(&self) -> usize {
        fn logs_bytes(logs: &Vec<IndexedLog>) -> usize {
            logs.capacity() * size_of::<IndexedLog>()
                + logs
                    .iter()
                    .map(|log| log.topics.capacity() * size_of::<B256>() + log.data.len())
                    .sum::<usize>()
        }
        size_of::<Self>()
            + self.block.transaction_hashes.capacity() * size_of::<B256>()
            + self.transactions.capacity() * size_of::<IndexedTransaction>()
            + self
                .transactions
                .iter()
                .map(|tx| tx.input.len() + tx.signer_did.as_ref().map_or(0, String::capacity))
                .sum::<usize>()
            + self.receipts.capacity() * size_of::<IndexedReceipt>()
            + self
                .receipts
                .iter()
                .map(|receipt| {
                    logs_bytes(&receipt.logs)
                        + receipt.signer_did.as_ref().map_or(0, String::capacity)
                        + receipt.refusal.as_ref().map_or(0, |r| r.message().len())
                })
                .sum::<usize>()
    }
}

pub(crate) fn matches_filter(log: &IndexedLog, filter: &LogFilter) -> bool {
    if let Some(addresses) = &filter.address
        && !addresses.contains(&log.address)
    {
        return false;
    }

    for (i, topic_filter) in filter.topics.iter().enumerate() {
        if let Some(allowed_topics) = topic_filter {
            match log.topics.get(i) {
                Some(log_topic) if allowed_topics.contains(log_topic) => {}
                _ => return false,
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, U256};

    use super::*;

    fn set_logs(index: &BlockIndex, hash: B256, logs: Vec<IndexedLog>) {
        let mut cache = index.cache.write();
        let revision = Arc::make_mut(cache.revisions.get_mut(&hash).unwrap());
        let mut receipt = create_test_receipt(B256::ZERO, hash, revision.block.number);
        receipt.logs = logs;
        revision.receipts = vec![receipt];
    }

    fn create_test_block(number: u64, hash: B256) -> IndexedBlock {
        IndexedBlock {
            hash,
            number,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp: 1000 + number,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            base_fee_per_gas: Some(1_000_000_000),
            transaction_hashes: vec![],
        }
    }

    fn create_test_tx(hash: B256, block_hash: B256, block_number: u64) -> IndexedTransaction {
        IndexedTransaction {
            hash,
            block_hash,
            block_number,
            transaction_index: 0,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            value: U256::ZERO,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            input: Bytes::new(),
            nonce: 0,
            signer_did: None,
        }
    }

    fn create_test_receipt(tx_hash: B256, block_hash: B256, block_number: u64) -> IndexedReceipt {
        IndexedReceipt {
            transaction_hash: tx_hash,
            block_hash,
            block_number,
            transaction_index: 0,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            cumulative_gas_used: 21_000,
            gas_used: 21_000,
            contract_address: None,
            logs: vec![],
            status: true,
            signer_did: None,
            refusal: None,
        }
    }

    #[test]
    fn eviction_preserves_readers_and_removes_all_lookup_entries() {
        let index = BlockIndex::new();
        let hash = B256::repeat_byte(1);
        let tx_hash = B256::repeat_byte(2);
        let mut block = create_test_block(1, hash);
        block.transaction_hashes = vec![tx_hash];
        let tx = IndexedTransaction {
            hash: tx_hash,
            block_hash: hash,
            block_number: 1,
            transaction_index: 0,
            from: Address::ZERO,
            to: None,
            value: U256::ZERO,
            gas_limit: 100,
            gas_price: 0,
            input: Bytes::new(),
            nonce: 73,
            signer_did: Some("owner".into()),
        };
        let receipt = IndexedReceipt {
            transaction_hash: tx_hash,
            block_hash: hash,
            block_number: 1,
            transaction_index: 0,
            from: Address::ZERO,
            to: None,
            cumulative_gas_used: 0,
            gas_used: 0,
            contract_address: None,
            logs: vec![],
            status: true,
            signer_did: Some("owner".into()),
            refusal: None,
        };
        index.insert_block(block, vec![tx], vec![receipt]);
        let retained = index.receipt_revision(&tx_hash).unwrap();
        for height in 2..=MAX_CACHED_REVISIONS as u64 + 1 {
            index.insert_block(
                create_test_block(height, B256::from(U256::from(height))),
                vec![],
                vec![],
            );
        }
        assert_eq!(index.block_count(), MAX_CACHED_REVISIONS);
        assert!(index.get_block_by_number(1).is_none());
        assert!(index.get_block_by_hash(&hash).is_none());
        assert!(index.get_transaction(&tx_hash).is_none());
        assert!(index.get_receipt(&tx_hash).is_none());
        assert!(index.receipt_revision(&tx_hash).is_none());
        assert_eq!(retained.receipts[0].transaction_hash, tx_hash);
        assert_eq!(retained.transactions[0].nonce, 73);
        assert_eq!(
            index.latest_block().unwrap().number,
            MAX_CACHED_REVISIONS as u64 + 1
        );
        // Replacing an old revision must not change the selected head or leak entries.
        index.insert_block(create_test_block(2, B256::repeat_byte(9)), vec![], vec![]);
        assert_eq!(index.block_count(), MAX_CACHED_REVISIONS);
        assert_eq!(index.head_block_number(), MAX_CACHED_REVISIONS as u64 + 1);
        assert!(
            index
                .get_block_by_hash(&B256::from(U256::from(2)))
                .is_none()
        );
    }

    #[test]
    fn byte_budget_keeps_only_an_oversized_head_until_it_is_replaced() {
        let index = BlockIndex::new();
        let mut large = create_test_block(2, B256::repeat_byte(2));
        large.transaction_hashes = Vec::with_capacity(MAX_CACHED_BYTES / size_of::<B256>());
        index.insert_block(create_test_block(1, B256::repeat_byte(1)), vec![], vec![]);
        index.insert_block(large, vec![], vec![]);
        assert_eq!(index.block_count(), 1);
        assert!(index.cache.read().bytes > MAX_CACHED_BYTES);
        assert_eq!(index.latest_block().unwrap().number, 2);
        index.insert_block(create_test_block(3, B256::repeat_byte(3)), vec![], vec![]);
        assert_eq!(index.block_count(), 1);
        assert!(index.cache.read().bytes < MAX_CACHED_BYTES);
        assert_eq!(index.latest_block().unwrap().number, 3);
    }

    #[test]
    fn test_insert_and_get_block() {
        let index = BlockIndex::new();
        let block_hash = B256::repeat_byte(1);
        let block = create_test_block(1, block_hash);

        index.insert_block(block, vec![], vec![]);

        let retrieved = index.get_block_by_hash(&block_hash).unwrap();
        assert_eq!(retrieved.number, 1);
        assert_eq!(retrieved.hash, block_hash);

        let by_number = index.get_block_by_number(1).unwrap();
        assert_eq!(by_number.hash, block_hash);
    }

    #[test]
    fn test_insert_and_get_transaction() {
        let index = BlockIndex::new();
        let block_hash = B256::repeat_byte(1);
        let tx_hash = B256::repeat_byte(2);
        let block = create_test_block(1, block_hash);
        let tx = create_test_tx(tx_hash, block_hash, 1);
        let receipt = create_test_receipt(tx_hash, block_hash, 1);

        index.insert_block(block, vec![tx], vec![receipt]);

        let retrieved_tx = index.get_transaction(&tx_hash).unwrap();
        assert_eq!(retrieved_tx.hash, tx_hash);

        let retrieved_receipt = index.get_receipt(&tx_hash).unwrap();
        assert_eq!(retrieved_receipt.transaction_hash, tx_hash);
    }

    #[test]
    fn test_head_block_number() {
        let index = BlockIndex::new();
        assert_eq!(index.head_block_number(), 0);

        index.insert_block(create_test_block(5, B256::repeat_byte(5)), vec![], vec![]);
        assert_eq!(index.head_block_number(), 5);

        index.insert_block(create_test_block(3, B256::repeat_byte(3)), vec![], vec![]);
        assert_eq!(index.head_block_number(), 5);

        index.insert_block(create_test_block(10, B256::repeat_byte(10)), vec![], vec![]);
        assert_eq!(index.head_block_number(), 10);
    }

    #[test]
    fn test_get_logs_with_filter() {
        let index = BlockIndex::new();
        let block_hash = B256::repeat_byte(1);
        let contract_addr = Address::repeat_byte(0xAB);
        let topic = B256::repeat_byte(0xCD);

        let log = IndexedLog {
            address: contract_addr,
            topics: vec![topic],
            data: Bytes::new(),
            log_index: 0,
            block_hash,
            block_number: 1,
            transaction_hash: B256::repeat_byte(2),
            transaction_index: 0,
        };

        let receipt = IndexedReceipt {
            transaction_hash: B256::repeat_byte(2),
            block_hash,
            block_number: 1,
            transaction_index: 0,
            from: Address::ZERO,
            to: None,
            cumulative_gas_used: 21_000,
            gas_used: 21_000,
            contract_address: None,
            logs: vec![log],
            status: true,
            signer_did: None,
            refusal: None,
        };

        index.insert_block(create_test_block(1, block_hash), vec![], vec![receipt]);

        let filter = LogFilter::new().address(vec![contract_addr]);
        let logs = index.get_logs(&filter).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, contract_addr);

        let filter = LogFilter::new().topic(0, vec![topic]);
        let logs = index.get_logs(&filter).unwrap();
        assert_eq!(logs.len(), 1);

        let filter = LogFilter::new().address(vec![Address::repeat_byte(0xFF)]);
        let logs = index.get_logs(&filter).unwrap();
        assert!(logs.is_empty());
    }

    #[test]
    fn log_queries_reject_excessive_work_and_results() {
        let index = BlockIndex::new();
        assert!(matches!(
            index.get_logs(&LogFilter::new().to_block(u64::MAX)),
            Err(IndexerError::LogQueryLimit)
        ));
        assert!(matches!(
            index.get_logs(&LogFilter::new().from_block(2).to_block(1)),
            Err(IndexerError::InvalidBlockRange { .. })
        ));
        assert!(
            index
                .get_logs(&LogFilter::new().to_block(9_999))
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            index.get_logs(&LogFilter::new().address(vec![Address::ZERO; 65])),
            Err(IndexerError::LogQueryLimit)
        ));
        assert!(matches!(
            index.get_logs(&LogFilter::new().topic(0, vec![B256::ZERO; 65])),
            Err(IndexerError::LogQueryLimit)
        ));
        let hash = B256::repeat_byte(1);
        index.insert_block(create_test_block(1, hash), vec![], vec![]);
        let mut log = IndexedLog {
            address: Address::ZERO,
            topics: vec![],
            data: Bytes::new(),
            log_index: 0,
            block_hash: hash,
            block_number: 1,
            transaction_hash: B256::ZERO,
            transaction_index: 0,
        };
        set_logs(&index, hash, vec![log.clone(); 1_000]);
        assert_eq!(index.get_logs(&LogFilter::new()).unwrap().len(), 1_000);
        set_logs(&index, hash, vec![log.clone(); 1_001]);
        assert!(matches!(
            index.get_logs(&LogFilter::new()),
            Err(IndexerError::LogQueryLimit)
        ));
        set_logs(&index, hash, vec![log.clone(); 10_001]);
        let unmatched = LogFilter::new().address(vec![Address::repeat_byte(1)]);
        assert!(matches!(
            index.get_logs(&unmatched),
            Err(IndexerError::LogQueryLimit)
        ));
        log.data = Bytes::from(vec![0; 1 << 20]);
        set_logs(&index, hash, vec![log]);
        assert!(matches!(
            index.get_logs(&LogFilter::new()),
            Err(IndexerError::LogQueryLimit)
        ));
        assert!(index.get_logs(&unmatched).unwrap().is_empty());
    }

    #[test]
    fn test_is_empty() {
        let index = BlockIndex::new();
        assert!(index.is_empty());

        index.insert_block(create_test_block(1, B256::repeat_byte(1)), vec![], vec![]);
        assert!(!index.is_empty());
    }

    #[test]
    fn test_block_count() {
        let index = BlockIndex::new();
        assert_eq!(index.block_count(), 0);

        index.insert_block(create_test_block(1, B256::repeat_byte(1)), vec![], vec![]);
        assert_eq!(index.block_count(), 1);

        index.insert_block(create_test_block(2, B256::repeat_byte(2)), vec![], vec![]);
        assert_eq!(index.block_count(), 2);
    }

    #[test]
    fn test_stats() {
        let index = BlockIndex::new();

        let stats = index.stats();
        assert_eq!(stats.cached_bytes, 0);
        assert_eq!(stats.block_count, 0);
        assert_eq!(stats.transaction_count, 0);
        assert_eq!(stats.receipt_count, 0);
        assert_eq!(stats.head_block_number, 0);

        let block_hash = B256::repeat_byte(1);
        let tx_hash = B256::repeat_byte(2);
        let tx = create_test_tx(tx_hash, block_hash, 5);
        let receipt = create_test_receipt(tx_hash, block_hash, 5);

        index.insert_block(create_test_block(5, block_hash), vec![tx], vec![receipt]);

        let stats = index.stats();
        assert!(stats.cached_bytes > 0);
        assert_eq!(stats.block_count, 1);
        assert_eq!(stats.transaction_count, 1);
        assert_eq!(stats.receipt_count, 1);
        assert_eq!(stats.head_block_number, 5);
    }
}
