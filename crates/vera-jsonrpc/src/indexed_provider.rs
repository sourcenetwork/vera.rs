//! Indexed state provider for production RPC use.
//!
//! Integrates the block indexer with ledger state to provide a complete
//! [`StateProvider`] implementation for RPC queries.

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U64, U256};
use async_trait::async_trait;
use vera_indexer::{BlockIndex, IndexedBlock, IndexedReceipt, IndexedTransaction, LogFilter};
use vera_traits::{StateDbError, StateDbRead};

use vera_domain::{NativeCallRequest, NativeCallSimulation};
use vera_executor::{
    ExecutionConfig, SharedModuleState, SimulateRequest, SpecId,
    estimate_gas as executor_estimate_gas, simulate_call,
};

mod simulation;

use crate::{
    error::RpcError,
    simulation_slots::SimulationSlots,
    state_provider::StateProvider,
    types::{
        BlockNumberOrTag, BlockTag, BlockTransactions, CallRequest, RpcBlock, RpcLog, RpcLogFilter,
        RpcTransaction, RpcTransactionReceipt,
    },
};

/// State provider that combines indexed block data with live state queries.
///
/// Uses [`BlockIndex`] for block, transaction, and receipt lookups, and
/// delegates account state queries (balance, nonce, code, storage) to
/// a generic state database implementation.
#[derive(Debug)]
pub struct IndexedStateProvider<S> {
    index: Arc<BlockIndex>,
    state: S,
    config: ExecutionConfig,
    block_gas_limit: u64,
    modules: SharedModuleState,
    archive: Option<crate::ArchiveReader>,
    simulations: SimulationSlots,
}

impl<S> IndexedStateProvider<S> {
    /// Creates a new indexed state provider.
    #[must_use]
    pub fn new(
        index: Arc<BlockIndex>,
        state: S,
        chain_id: u64,
        spec_id: SpecId,
        block_gas_limit: u64,
        modules: SharedModuleState,
    ) -> Self {
        Self {
            index,
            state,
            config: ExecutionConfig::new(chain_id).with_spec_id(spec_id),
            block_gas_limit,
            modules,
            archive: None,
            simulations: SimulationSlots::default(),
        }
    }
}

impl<S> IndexedStateProvider<S> {
    /// Simulate under the deployment's execution configuration, which binds
    /// the genesis record and the membership limit module calls observe.
    #[must_use]
    pub const fn with_execution_config(mut self, config: ExecutionConfig) -> Self {
        self.config = config;
        self
    }

    /// Enable bounded historical point reads when entries are absent from memory.
    pub fn with_archive(mut self, archive: crate::ArchiveReader) -> Self {
        self.archive = Some(archive);
        self
    }
}

impl<S: Clone> Clone for IndexedStateProvider<S> {
    fn clone(&self) -> Self {
        Self {
            index: Arc::clone(&self.index),
            state: self.state.clone(),
            config: self.config.clone(),
            block_gas_limit: self.block_gas_limit,
            modules: Arc::clone(&self.modules),
            archive: self.archive.clone(),
            simulations: self.simulations.clone(),
        }
    }
}

#[async_trait]
impl<S: StateDbRead + Send + Sync + 'static> StateProvider for IndexedStateProvider<S> {
    async fn balance(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> Result<U256, RpcError> {
        reject_historical_block(&block)?;
        self.state
            .balance(&address)
            .await
            .map_err(state_error_to_rpc)
    }

    async fn nonce(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> Result<u64, RpcError> {
        reject_historical_block(&block)?;
        self.state.nonce(&address).await.map_err(state_error_to_rpc)
    }

    async fn code(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> Result<Bytes, RpcError> {
        reject_historical_block(&block)?;
        let code_hash = self
            .state
            .code_hash(&address)
            .await
            .map_err(state_error_to_rpc)?;
        // An account without code has no code record to read.
        if code_hash == KECCAK256_EMPTY || code_hash == B256::ZERO {
            return Ok(Bytes::new());
        }
        self.state
            .code(&code_hash)
            .await
            .map_err(state_error_to_rpc)
    }

    async fn storage(
        &self,
        address: Address,
        slot: U256,
        block: Option<BlockNumberOrTag>,
    ) -> Result<U256, RpcError> {
        reject_historical_block(&block)?;
        self.state
            .storage(&address, &slot)
            .await
            .map_err(state_error_to_rpc)
    }

    async fn block_by_number(&self, block: BlockNumberOrTag) -> Result<Option<RpcBlock>, RpcError> {
        let block_num = self.resolve_block_number(&block)?;
        let mut indexed = self.index.get_block_by_number(block_num);
        if indexed.is_none()
            && let Some(archive) = &self.archive
        {
            indexed = archive
                .read(vera_indexer::IndexQuery::Revision(block_num))
                .await?
                .and_then(|index| index.get_block_by_number(block_num));
        }
        Ok(indexed.map(indexed_block_to_rpc))
    }

    async fn block_by_hash(&self, hash: B256) -> Result<Option<RpcBlock>, RpcError> {
        let mut indexed = self.index.get_block_by_hash(&hash);
        if indexed.is_none()
            && let Some(archive) = &self.archive
        {
            indexed = archive
                .read(vera_indexer::IndexQuery::RevisionHash(hash))
                .await?
                .and_then(|index| index.get_block_by_hash(&hash));
        }
        Ok(indexed.map(indexed_block_to_rpc))
    }

    async fn transaction_by_hash(&self, hash: B256) -> Result<Option<RpcTransaction>, RpcError> {
        let mut indexed = self.index.get_transaction(&hash);
        if indexed.is_none()
            && let Some(archive) = &self.archive
        {
            indexed = archive
                .read(vera_indexer::IndexQuery::Submission(hash))
                .await?
                .and_then(|index| index.get_transaction(&hash));
        }
        Ok(indexed.map(indexed_tx_to_rpc))
    }

    async fn receipt_by_hash(&self, hash: B256) -> Result<Option<RpcTransactionReceipt>, RpcError> {
        let mut indexed = self.index.get_receipt(&hash);
        if indexed.is_none()
            && let Some(archive) = &self.archive
        {
            indexed = archive
                .read(vera_indexer::IndexQuery::Submission(hash))
                .await?
                .and_then(|index| index.get_receipt(&hash));
        }
        Ok(indexed.map(indexed_receipt_to_rpc))
    }

    async fn block_number(&self) -> Result<u64, RpcError> {
        Ok(self.index.head_block_number())
    }

    async fn get_logs(&self, filter: RpcLogFilter) -> Result<Vec<RpcLog>, RpcError> {
        let (from_block, to_block) = if let Some(hash) = filter.block_hash {
            if filter.from_block.is_some() || filter.to_block.is_some() {
                return Err(RpcError::InvalidParams(
                    "blockHash cannot be combined with fromBlock or toBlock".into(),
                ));
            }
            let number = self.revision_number(hash).await?;
            (Some(number), Some(number))
        } else {
            (
                filter
                    .from_block
                    .as_ref()
                    .map(|b| self.resolve_block_number(b))
                    .transpose()?,
                filter
                    .to_block
                    .as_ref()
                    .map(|b| self.resolve_block_number(b))
                    .transpose()?,
            )
        };

        let mut log_filter = LogFilter::new();
        if let Some(from) = from_block {
            log_filter = log_filter.from_block(from);
        }
        if let Some(to) = to_block {
            log_filter = log_filter.to_block(to);
        }
        if let Some(addr_filter) = filter.address {
            log_filter = log_filter.address(addr_filter.into_vec());
        }
        if let Some(topics) = filter.topics {
            if topics.len() > vera_indexer::MAX_LOG_TOPIC_POSITIONS {
                return Err(RpcError::InvalidParams(
                    "a log filter constrains at most four topic positions".into(),
                ));
            }
            for (i, topic_filter) in topics.into_iter().enumerate() {
                if let Some(tf) = topic_filter {
                    log_filter = log_filter.topic(i, tf.into_vec());
                }
            }
        }

        let indexed_logs = if let Some(archive) = &self.archive {
            archive.logs(self.index.clone(), log_filter).await?
        } else {
            self.index
                .get_logs(&log_filter)
                .map_err(crate::archive::log_error)?
        };
        let logs = indexed_logs
            .into_iter()
            .map(|log| RpcLog {
                address: log.address,
                topics: log.topics,
                data: log.data,
                block_number: U64::from(log.block_number),
                transaction_hash: log.transaction_hash,
                transaction_index: U64::from(log.transaction_index),
                block_hash: log.block_hash,
                log_index: U64::from(log.log_index),
                removed: false,
            })
            .collect();
        Ok(logs)
    }

    async fn call(
        &self,
        request: CallRequest,
        block: Option<BlockNumberOrTag>,
    ) -> Result<Bytes, RpcError> {
        reject_historical_block(&block)?;
        let request = call_request_to_simulate(&request);
        let context = self.head_context();
        let result = self
            .simulate(move |state, modules| simulate_call(state, &context, &request, Some(modules)))
            .await?;
        if result.success {
            Ok(result.output)
        } else {
            Err(RpcError::ExecutionReverted {
                data: format!("0x{}", hex::encode(&result.output)),
            })
        }
    }

    async fn estimate_gas(
        &self,
        request: CallRequest,
        block: Option<BlockNumberOrTag>,
    ) -> Result<u64, RpcError> {
        reject_historical_block(&block)?;
        let request = call_request_to_simulate(&request);
        let context = self.head_context();
        self.simulate(move |state, modules| {
            executor_estimate_gas(state, &context, &request, Some(modules))
        })
        .await
    }

    async fn simulate_native_call(
        &self,
        request: NativeCallRequest,
    ) -> Result<NativeCallSimulation, RpcError> {
        self.simulate_native(request).await
    }
}

impl<S> IndexedStateProvider<S> {
    async fn revision_number(&self, hash: B256) -> Result<u64, RpcError> {
        if let Some(block) = self.index.get_block_by_hash(&hash) {
            return Ok(block.number);
        }
        let archived = match &self.archive {
            Some(archive) => archive
                .read(vera_indexer::IndexQuery::RevisionHash(hash))
                .await?
                .and_then(|index| index.get_block_by_hash(&hash)),
            None => None,
        };
        archived
            .map(|block| block.number)
            .ok_or_else(|| RpcError::InvalidParams(format!("unknown block hash {hash}")))
    }

    fn resolve_block_number(&self, block: &BlockNumberOrTag) -> Result<u64, RpcError> {
        match block {
            BlockNumberOrTag::Number(n) => Ok(n.to::<u64>()),
            BlockNumberOrTag::Tag(tag) => self.resolve_tag(*tag),
            BlockNumberOrTag::Latest => Ok(self.index.head_block_number()),
        }
    }

    fn resolve_tag(&self, tag: BlockTag) -> Result<u64, RpcError> {
        match tag {
            BlockTag::Latest | BlockTag::Safe | BlockTag::Finalized | BlockTag::Pending => {
                Ok(self.index.head_block_number())
            }
            BlockTag::Earliest => Ok(0),
        }
    }
}

const fn reject_historical_block(block: &Option<BlockNumberOrTag>) -> Result<(), RpcError> {
    match block {
        None | Some(BlockNumberOrTag::Latest) => Ok(()),
        Some(BlockNumberOrTag::Tag(
            BlockTag::Latest | BlockTag::Safe | BlockTag::Finalized | BlockTag::Pending,
        )) => Ok(()),
        Some(BlockNumberOrTag::Number(_) | BlockNumberOrTag::Tag(BlockTag::Earliest)) => {
            Err(RpcError::NotImplemented)
        }
    }
}

fn call_request_to_simulate(request: &CallRequest) -> SimulateRequest {
    let data = request
        .input
        .clone()
        .or_else(|| request.data.clone())
        .unwrap_or_default();
    SimulateRequest {
        from: request.from.unwrap_or(Address::ZERO),
        to: request.to,
        value: request.value.unwrap_or(U256::ZERO),
        data,
        gas: request.gas.map(|g| g.to::<u64>()),
    }
}

fn state_error_to_rpc(err: StateDbError) -> RpcError {
    match err {
        StateDbError::AccountNotFound(addr) => RpcError::AccountNotFound(addr.to_string()),
        StateDbError::CodeNotFound(hash) => RpcError::StateError(format!("code not found: {hash}")),
        StateDbError::Storage(msg) => RpcError::StateError(msg),
    }
}

fn indexed_block_to_rpc(block: IndexedBlock) -> RpcBlock {
    RpcBlock {
        hash: block.hash,
        parent_hash: block.parent_hash,
        number: U64::from(block.number),
        state_root: block.state_root,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Bytes::new(),
        timestamp: U64::from(block.timestamp),
        gas_limit: U64::from(block.gas_limit),
        gas_used: U64::from(block.gas_used),
        extra_data: Bytes::new(),
        mix_hash: block.prevrandao,
        nonce: Default::default(),
        base_fee_per_gas: block.base_fee_per_gas.map(U256::from),
        miner: Address::ZERO,
        difficulty: U256::ZERO,
        total_difficulty: U256::ZERO,
        uncles: vec![],
        size: U64::ZERO,
        transactions: BlockTransactions::Hashes(block.transaction_hashes),
    }
}

fn indexed_tx_to_rpc(tx: IndexedTransaction) -> RpcTransaction {
    RpcTransaction {
        hash: tx.hash,
        nonce: U64::from(tx.nonce),
        block_hash: Some(tx.block_hash),
        block_number: Some(U64::from(tx.block_number)),
        transaction_index: Some(U64::from(tx.transaction_index)),
        from: tx.from,
        to: tx.to,
        value: tx.value,
        gas: U64::from(tx.gas_limit),
        gas_price: U256::from(tx.gas_price),
        input: tx.input,
        tx_type: U64::ZERO,
        chain_id: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        v: U64::ZERO,
        r: U256::ZERO,
        s: U256::ZERO,
    }
}

fn indexed_receipt_to_rpc(receipt: IndexedReceipt) -> RpcTransactionReceipt {
    let logs = receipt
        .logs
        .into_iter()
        .map(|log| RpcLog {
            address: log.address,
            topics: log.topics,
            data: log.data,
            block_number: U64::from(receipt.block_number),
            transaction_hash: receipt.transaction_hash,
            transaction_index: U64::from(receipt.transaction_index),
            block_hash: receipt.block_hash,
            log_index: U64::from(log.log_index),
            removed: false,
        })
        .collect();

    RpcTransactionReceipt {
        transaction_hash: receipt.transaction_hash,
        transaction_index: U64::from(receipt.transaction_index),
        block_hash: receipt.block_hash,
        block_number: U64::from(receipt.block_number),
        from: receipt.from,
        to: receipt.to,
        cumulative_gas_used: U64::from(receipt.cumulative_gas_used),
        gas_used: U64::from(receipt.gas_used),
        contract_address: receipt.contract_address,
        logs,
        logs_bloom: Bytes::new(),
        tx_type: U64::ZERO,
        status: if receipt.status {
            U64::from(1)
        } else {
            U64::ZERO
        },
        effective_gas_price: U256::ZERO,
    }
}

#[cfg(test)]
#[path = "indexed_provider/simulation_tests.rs"]
mod simulation_tests;

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use vera_executor::ModuleState;
    use vera_indexer::IndexedLog;

    use super::*;
    use crate::simulation_slots::{SIMULATION_SLOTS, SIMULATION_WAITERS};
    use vera_executor::SpecId;

    #[tokio::test]
    async fn log_query_limits_reach_rpc_clients() {
        let provider = IndexedStateProvider::new(
            Arc::new(BlockIndex::new()),
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );
        let filter = RpcLogFilter {
            to_block: Some(BlockNumberOrTag::Number(U64::from(u64::MAX))),
            ..Default::default()
        };
        let error: jsonrpsee::types::ErrorObjectOwned =
            provider.get_logs(filter).await.unwrap_err().into();
        assert_eq!(error.code(), crate::error::codes::LIMIT_EXCEEDED);
        let filter = RpcLogFilter {
            from_block: Some(BlockNumberOrTag::Number(U64::from(2))),
            to_block: Some(BlockNumberOrTag::Number(U64::from(1))),
            ..Default::default()
        };
        let error: jsonrpsee::types::ErrorObjectOwned =
            provider.get_logs(filter).await.unwrap_err().into();
        assert_eq!(error.code(), crate::error::codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn archive_log_ranges_share_limits_with_resident_revisions() {
        use crate::{ArchiveReader, NodeState};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use vera_indexer::{IndexQuery, IndexedLog};
        let resident = Arc::new(BlockIndex::new());
        let retained = Arc::new(BlockIndex::new());
        for (height, index) in [(1, &retained), (2, &resident)] {
            let hash = B256::with_last_byte(height as u8);
            let mut receipt = create_test_receipt(hash, hash, height);
            receipt.logs = vec![
                IndexedLog {
                    address: Address::ZERO,
                    topics: vec![],
                    data: Bytes::new(),
                    log_index: 0,
                    block_hash: hash,
                    block_number: height,
                    transaction_hash: hash,
                    transaction_index: 0,
                };
                501
            ];
            index.insert_block(create_test_block(height, hash), vec![], vec![receipt]);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let state = NodeState::new(1, 0, 1);
        let archive = ArchiveReader::new(state.clone(), {
            let calls = calls.clone();
            let retained = retained.clone();
            Arc::new(move |query, budget| {
                calls.fetch_add(1, Ordering::Relaxed);
                assert!(matches!(query, IndexQuery::Revision(1)));
                assert_eq!(*budget, 64 << 20);
                Ok(Some(retained.clone()))
            })
        });
        let filter = LogFilter::new().from_block(1).to_block(2);
        assert!(matches!(
            archive.logs(resident.clone(), filter.clone()).await,
            Err(RpcError::LimitExceeded(_))
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let logs = archive
            .logs(resident.clone(), LogFilter::new().from_block(2).to_block(2))
            .await
            .unwrap();
        assert_eq!(logs.len(), 501);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let logs = archive
            .logs(resident.clone(), LogFilter::new().from_block(1).to_block(1))
            .await
            .unwrap();
        assert_eq!(logs.len(), 501);
        assert!(logs.iter().all(|log| log.block_number == 1));
        let unmatched = filter.clone().address(vec![Address::repeat_byte(1)]);
        assert!(
            archive
                .logs(resident.clone(), unmatched)
                .await
                .unwrap()
                .is_empty()
        );
        let permits = (0..8)
            .map(|_| state.light_lookup_permit().unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            archive.logs(resident.clone(), filter.clone()).await,
            Err(RpcError::HistoryBusy)
        ));
        drop(permits);
        let broken = ArchiveReader::new(
            state,
            Arc::new(|_, _| Err(RpcError::StateError("unready".into()))),
        );
        assert!(matches!(
            broken.logs(resident, filter).await,
            Err(RpcError::StateError(_))
        ));
    }

    #[tokio::test]
    async fn archive_point_reads_match_memory_and_propagate_failures() {
        use crate::{ArchiveReader, NodeState, VeraApiImpl, VeraApiServer};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use vera_indexer::IndexQuery;
        let hash = B256::repeat_byte(7);
        let tx_hash = B256::repeat_byte(8);
        let index = Arc::new(BlockIndex::new());
        let mut block = create_test_block(1, hash);
        block.transaction_hashes = vec![tx_hash];
        let mut tx = create_test_tx(tx_hash, hash, 1);
        tx.nonce = 73;
        tx.signer_did = Some("did:key:retained-owner".into());
        let mut receipt = create_test_receipt(tx_hash, hash, 1);
        receipt.signer_did = tx.signer_did.clone();
        let evicted = Arc::new(BlockIndex::new());
        evicted.insert_block(block.clone(), vec![tx.clone()], vec![receipt.clone()]);
        for number in 2..=vera_indexer::MAX_CACHED_REVISIONS as u64 + 1 {
            evicted.insert_block(
                create_test_block(number, B256::from(U256::from(number))),
                vec![],
                vec![],
            );
        }
        assert!(evicted.get_receipt(&tx_hash).is_none());
        index.insert_block(block, vec![tx], vec![receipt]);
        let state = NodeState::new(1, 0, 1);
        let calls = Arc::new(AtomicUsize::new(0));
        let archive = ArchiveReader::new(state.clone(), {
            let calls = calls.clone();
            let index = index.clone();
            Arc::new(move |query, _remaining_bytes| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(match query {
                    IndexQuery::Revision(1) => Some(index.clone()),
                    IndexQuery::RevisionHash(id) if id == hash => Some(index.clone()),
                    IndexQuery::Submission(id) if id == tx_hash => Some(index.clone()),
                    _ => None,
                })
            })
        });
        let hot = IndexedStateProvider::new(
            index.clone(),
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        )
        .with_archive(archive.clone());
        let cold = IndexedStateProvider::new(
            evicted.clone(),
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        )
        .with_archive(archive.clone());
        let height = BlockNumberOrTag::Number(U64::from(1));
        let expected = serde_json::to_value((
            hot.block_by_number(height.clone()).await.unwrap(),
            hot.block_by_hash(hash).await.unwrap(),
            hot.transaction_by_hash(tx_hash).await.unwrap(),
            hot.receipt_by_hash(tx_hash).await.unwrap(),
        ))
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let actual = serde_json::to_value((
            cold.block_by_number(height).await.unwrap(),
            cold.block_by_hash(hash).await.unwrap(),
            cold.transaction_by_hash(tx_hash).await.unwrap(),
            cold.receipt_by_hash(tx_hash).await.unwrap(),
        ))
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        let hot_api = VeraApiImpl::new(Arc::new(state.clone()), None)
            .with_index_and_modules(index, default_modules());
        let cold_api = VeraApiImpl::new(Arc::new(state.clone()), None)
            .with_index_and_modules(evicted, default_modules())
            .with_archive(archive);
        let expected = hot_api
            .get_transaction_receipt(tx_hash)
            .await
            .unwrap()
            .unwrap();
        let actual = cold_api
            .get_transaction_receipt(tx_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual.native_nonce, Some(U64::from(73)));
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert!(
            cold.transaction_by_hash(B256::ZERO)
                .await
                .unwrap()
                .is_none()
        );
        let _held: Vec<_> = (0..8)
            .map(|_| state.light_lookup_permit().unwrap())
            .collect();
        let error: jsonrpsee::types::ErrorObjectOwned =
            cold.receipt_by_hash(tx_hash).await.unwrap_err().into();
        assert_eq!(error.code(), crate::error::codes::RESOURCE_UNAVAILABLE);
        assert_eq!(error.data().unwrap().get(), r#"{"retryable":true}"#);
        let broken = cold.with_archive(ArchiveReader::new(
            NodeState::new(1, 0, 1),
            Arc::new(|_, _| Err(RpcError::StateError("unready archive".into()))),
        ));
        assert!(matches!(
            broken.block_by_hash(hash).await,
            Err(RpcError::StateError(_))
        ));
    }

    fn default_modules() -> SharedModuleState {
        Arc::new(RwLock::new(ModuleState::default()))
    }

    #[derive(Clone)]
    struct MockState;

    impl StateDbRead for MockState {
        async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
            Ok(42)
        }

        async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
            Ok(U256::from(1000))
        }

        async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }

        async fn code(&self, _code_hash: &B256) -> Result<Bytes, StateDbError> {
            Ok(Bytes::from_static(&[0x60, 0x00]))
        }

        async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
            Ok(U256::from(123))
        }
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
            prevrandao: B256::ZERO,
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
            logs: vec![IndexedLog {
                address: Address::ZERO,
                topics: vec![],
                data: Bytes::new(),
                log_index: 0,
                block_hash,
                block_number,
                transaction_hash: tx_hash,
                transaction_index: 0,
            }],
            status: true,
            signer_did: None,
        }
    }

    #[tokio::test]
    async fn test_balance() {
        let index = Arc::new(BlockIndex::new());
        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let balance = provider.balance(Address::ZERO, None).await.unwrap();
        assert_eq!(balance, U256::from(1000));
    }

    #[tokio::test]
    async fn test_nonce() {
        let index = Arc::new(BlockIndex::new());
        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let nonce = provider.nonce(Address::ZERO, None).await.unwrap();
        assert_eq!(nonce, 42);
    }

    #[tokio::test]
    async fn test_block_by_number() {
        let index = Arc::new(BlockIndex::new());
        let block_hash = B256::repeat_byte(1);
        index.insert_block(create_test_block(1, block_hash), vec![], vec![]);

        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let block = provider
            .block_by_number(BlockNumberOrTag::Number(U64::from(1)))
            .await
            .unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().hash, block_hash);
    }

    #[tokio::test]
    async fn test_block_by_hash() {
        let index = Arc::new(BlockIndex::new());
        let block_hash = B256::repeat_byte(1);
        index.insert_block(create_test_block(1, block_hash), vec![], vec![]);

        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let block = provider.block_by_hash(block_hash).await.unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().number, U64::from(1));
    }

    #[tokio::test]
    async fn test_transaction_by_hash() {
        let index = Arc::new(BlockIndex::new());
        let block_hash = B256::repeat_byte(1);
        let tx_hash = B256::repeat_byte(2);
        index.insert_block(
            create_test_block(1, block_hash),
            vec![create_test_tx(tx_hash, block_hash, 1)],
            vec![],
        );

        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let tx = provider.transaction_by_hash(tx_hash).await.unwrap();
        assert!(tx.is_some());
        assert_eq!(tx.unwrap().hash, tx_hash);
    }

    #[tokio::test]
    async fn test_receipt_by_hash() {
        let index = Arc::new(BlockIndex::new());
        let block_hash = B256::repeat_byte(1);
        let tx_hash = B256::repeat_byte(2);
        index.insert_block(
            create_test_block(1, block_hash),
            vec![create_test_tx(tx_hash, block_hash, 1)],
            vec![create_test_receipt(tx_hash, block_hash, 1)],
        );

        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let receipt = provider.receipt_by_hash(tx_hash).await.unwrap();
        assert!(receipt.is_some());
        let receipt = receipt.unwrap();
        assert_eq!(receipt.transaction_hash, tx_hash);
        assert_eq!(receipt.logs.len(), 1);
    }

    #[tokio::test]
    async fn test_block_number() {
        let index = Arc::new(BlockIndex::new());
        index.insert_block(create_test_block(5, B256::repeat_byte(5)), vec![], vec![]);

        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let num = provider.block_number().await.unwrap();
        assert_eq!(num, 5);
    }

    #[tokio::test]
    async fn test_resolve_block_tags() {
        let index = Arc::new(BlockIndex::new());
        index.insert_block(create_test_block(10, B256::repeat_byte(10)), vec![], vec![]);

        let provider = IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );

        let block = provider
            .block_by_number(BlockNumberOrTag::Tag(BlockTag::Latest))
            .await
            .unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().number, U64::from(10));

        let block = provider
            .block_by_number(BlockNumberOrTag::Tag(BlockTag::Earliest))
            .await
            .unwrap();
        assert!(block.is_none());
    }

    fn provider(index: Arc<BlockIndex>) -> IndexedStateProvider<MockState> {
        IndexedStateProvider::new(
            index,
            MockState,
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        )
    }

    #[tokio::test]
    async fn state_reads_reject_historical_selectors() {
        let provider = provider(Arc::new(BlockIndex::new()));
        let address = Address::ZERO;
        for block in [
            BlockNumberOrTag::Number(U64::from(16)),
            BlockNumberOrTag::Tag(BlockTag::Earliest),
        ] {
            let block = Some(block);
            for error in [
                provider.balance(address, block.clone()).await.unwrap_err(),
                provider
                    .storage(address, U256::ZERO, block.clone())
                    .await
                    .unwrap_err(),
                provider
                    .nonce(address, block.clone())
                    .await
                    .map(|_| ())
                    .unwrap_err(),
                provider
                    .code(address, block.clone())
                    .await
                    .map(|_| ())
                    .unwrap_err(),
            ] {
                assert!(matches!(error, RpcError::NotImplemented));
            }
        }
        for block in [
            None,
            Some(BlockNumberOrTag::Latest),
            Some(BlockNumberOrTag::Tag(BlockTag::Finalized)),
        ] {
            assert!(provider.balance(address, block.clone()).await.is_ok());
            assert!(provider.nonce(address, block.clone()).await.is_ok());
            assert!(provider.code(address, block.clone()).await.is_ok());
            assert!(provider.storage(address, U256::ZERO, block).await.is_ok());
        }
    }

    #[tokio::test]
    async fn log_queries_by_block_hash_select_that_revision_only() {
        use crate::{ArchiveReader, NodeState};
        let resident = Arc::new(BlockIndex::new());
        let retained = Arc::new(BlockIndex::new());
        let hashes = [B256::with_last_byte(1), B256::with_last_byte(2)];
        for (height, index) in [(1, &retained), (2, &resident)] {
            let hash = hashes[height as usize - 1];
            index.insert_block(
                create_test_block(height, hash),
                vec![],
                vec![create_test_receipt(hash, hash, height)],
            );
        }
        let archived = hashes[0];
        let archive = ArchiveReader::new(NodeState::new(1, 0, 1), {
            let retained = retained.clone();
            Arc::new(move |query, _| {
                Ok(match query {
                    vera_indexer::IndexQuery::Revision(1) => Some(retained.clone()),
                    vera_indexer::IndexQuery::RevisionHash(hash) if hash == archived => {
                        Some(retained.clone())
                    }
                    _ => None,
                })
            })
        });
        let provider = provider(resident).with_archive(archive);
        let by_hash = |hash| RpcLogFilter {
            block_hash: Some(hash),
            ..Default::default()
        };
        for (hash, height) in [(hashes[0], 1), (hashes[1], 2)] {
            let logs = provider.get_logs(by_hash(hash)).await.unwrap();
            assert_eq!(logs.len(), 1);
            assert_eq!(logs[0].block_hash, hash);
            assert_eq!(logs[0].block_number, U64::from(height));
        }
        assert_eq!(
            provider
                .get_logs(RpcLogFilter::default())
                .await
                .unwrap()
                .len(),
            2
        );
        for filter in [
            by_hash(B256::repeat_byte(9)),
            RpcLogFilter {
                from_block: Some(BlockNumberOrTag::Number(U64::from(1))),
                ..by_hash(hashes[1])
            },
            RpcLogFilter {
                topics: Some(vec![None; 5]),
                ..Default::default()
            },
        ] {
            let error: jsonrpsee::types::ErrorObjectOwned =
                provider.get_logs(filter).await.unwrap_err().into();
            assert_eq!(error.code(), crate::error::codes::INVALID_PARAMS);
        }
    }

    type Gate = (
        tokio::sync::mpsc::UnboundedSender<()>,
        std::sync::mpsc::Receiver<()>,
    );

    /// Blocks its first account read until released, as a slow execution would.
    #[derive(Clone)]
    struct GatedState(Arc<std::sync::Mutex<Option<Gate>>>);

    impl StateDbRead for GatedState {
        async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
            let gate = self.0.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            Ok(0)
        }

        async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
            Ok(U256::MAX)
        }

        async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
            Ok(KECCAK256_EMPTY)
        }

        async fn code(&self, _code_hash: &B256) -> Result<Bytes, StateDbError> {
            Ok(Bytes::new())
        }

        async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }
    }

    #[tokio::test]
    async fn simulations_run_off_the_module_lock_under_bounded_admission() {
        let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
        let (release, gate) = std::sync::mpsc::channel();
        let modules = default_modules();
        let provider = IndexedStateProvider::new(
            Arc::new(BlockIndex::new()),
            GatedState(Arc::new(std::sync::Mutex::new(Some((entered, gate))))),
            1,
            SpecId::CANCUN,
            30_000_000,
            modules.clone(),
        );
        let request = || CallRequest {
            to: Some(Address::repeat_byte(1)),
            ..Default::default()
        };
        let running = provider.clone();
        let call = tokio::spawn(async move { running.call(request(), None).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), entries.recv())
            .await
            .unwrap()
            .unwrap();
        // Finalization publishes module state while the execution is still running.
        drop(
            modules
                .try_write()
                .expect("simulation must not hold the module lock"),
        );
        let mut others = Vec::new();
        for _ in 1..SIMULATION_SLOTS {
            others.push(provider.simulations.acquire().await.unwrap());
        }
        let queued = provider.clone();
        let estimate = tokio::spawn(async move { queued.estimate_gas(request(), None).await });
        wait_for_waiters(&provider.simulations, 1).await;
        assert!(!estimate.is_finished());
        let waiters: Vec<_> = (1..SIMULATION_WAITERS)
            .map(|_| {
                let slots = provider.simulations.clone();
                tokio::spawn(async move { slots.acquire().await.map(drop) })
            })
            .collect();
        wait_for_waiters(&provider.simulations, SIMULATION_WAITERS).await;
        let busy: jsonrpsee::types::ErrorObjectOwned = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            provider.call(request(), None),
        )
        .await
        .expect("a full queue must refuse without waiting for a slot")
        .unwrap_err()
        .into();
        assert_eq!(busy.code(), crate::error::codes::RESOURCE_UNAVAILABLE);
        assert_eq!(busy.data().unwrap().get(), r#"{"retryable":true}"#);
        release.send(()).unwrap();
        assert!(call.await.unwrap().unwrap().is_empty());
        assert!(estimate.await.unwrap().unwrap() >= 21_000);
        drop(others);
        for waiter in waiters {
            waiter.await.unwrap().unwrap();
        }
    }

    /// Returns once `waiters` callers queue behind fully occupied slots.
    async fn wait_for_waiters(slots: &SimulationSlots, waiters: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while slots.free_places() != SIMULATION_WAITERS - waiters {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    /// Holds accounts without code and no code records, as committed state does.
    #[derive(Clone)]
    struct CodelessState(B256);

    impl StateDbRead for CodelessState {
        async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
            Ok(0)
        }

        async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }

        async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
            Ok(self.0)
        }

        async fn code(&self, code_hash: &B256) -> Result<Bytes, StateDbError> {
            Err(StateDbError::CodeNotFound(*code_hash))
        }

        async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }
    }

    #[tokio::test]
    async fn an_account_without_code_reads_as_empty_code() {
        for hash in [KECCAK256_EMPTY, B256::ZERO] {
            let provider = IndexedStateProvider::new(
                Arc::new(BlockIndex::new()),
                CodelessState(hash),
                1,
                SpecId::CANCUN,
                30_000_000,
                default_modules(),
            );
            assert!(provider.code(Address::ZERO, None).await.unwrap().is_empty());
        }
        let missing = IndexedStateProvider::new(
            Arc::new(BlockIndex::new()),
            CodelessState(B256::repeat_byte(7)),
            1,
            SpecId::CANCUN,
            30_000_000,
            default_modules(),
        );
        assert!(matches!(
            missing.code(Address::ZERO, None).await,
            Err(RpcError::StateError(_))
        ));
    }
}
