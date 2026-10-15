//! The glue stateful application.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{ApplicationState, VrfSeedCache, ordered_state::OrderedState};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use commonware_consensus::types::Round;
use commonware_consensus::{Handoff, marshal::ancestry::Ancestry};
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::{Application, Input, Proposed};
use futures::StreamExt as _;
use std::marker::PhantomData;
use tracing::{info, warn};
use vera_backend::Ctx;
use vera_consensus::{Mempool as _, TxId, components::InMemoryMempool};
use vera_domain::{Block, ConsensusContext, PublicKey};
use vera_executor::{BlockContext, ExecutionReceipt, VeraExecutor, receipt_commitment};

use crate::{AppError, ConsensusScheme, FinalizedSink, ReshareInput};

const MAX_CLOCK_DRIFT_SECS: u64 = 15;
const MAX_PENDING_ANCESTORS: usize = 64;

/// Vera block production and verification on top of glue-managed state.
#[derive(Clone)]
pub struct StatefulVeraApp<S: FinalizedSink, D: ApplicationState = OrderedState> {
    storage: PhantomData<D>,
    executor: VeraExecutor,
    genesis: Block,
    mempool: InMemoryMempool,
    sink: S,
    max_txs: usize,
    gas_limit: u64,
    participant_addresses: Arc<Vec<(PublicKey, Address)>>,
    vrf_seeds: VrfSeedCache,
    native_pipeline: bool,
    proposal_batch_wait: std::time::Duration,
}

impl<S: FinalizedSink, D: ApplicationState> std::fmt::Debug for StatefulVeraApp<S, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatefulVeraApp")
            .field("max_txs", &self.max_txs)
            .field("gas_limit", &self.gas_limit)
            .finish_non_exhaustive()
    }
}

impl<S: FinalizedSink, D: ApplicationState> StatefulVeraApp<S, D> {
    /// Create the application around an executor and the genesis block.
    pub fn new(
        executor: VeraExecutor,
        genesis: Block,
        mempool: InMemoryMempool,
        sink: S,
        max_txs: usize,
        gas_limit: u64,
    ) -> Self {
        assert!(
            D::accepts(&genesis),
            "genesis storage layout does not match application"
        );
        Self {
            storage: PhantomData,
            executor,
            genesis,
            mempool,
            sink,
            max_txs,
            gas_limit,
            participant_addresses: Arc::new(Vec::new()),
            vrf_seeds: VrfSeedCache::default(),
            native_pipeline: false,
            proposal_batch_wait: std::time::Duration::ZERO,
        }
    }

    /// Map consensus leaders to the EVM address credited as block beneficiary.
    #[must_use]
    pub fn with_participant_addresses(mut self, addrs: Vec<(PublicKey, Address)>) -> Self {
        self.participant_addresses = Arc::new(addrs);
        self
    }

    /// Enable native-only execution without certificate-dependent EVM randomness.
    #[must_use]
    pub const fn with_native_pipeline(
        mut self,
        enabled: bool,
        batch_wait: std::time::Duration,
    ) -> Self {
        self.native_pipeline = enabled;
        self.proposal_batch_wait = batch_wait;
        self
    }

    /// Shared cache populated by the node's VRF-aware consensus elector.
    #[must_use]
    pub fn vrf_seed_cache(&self) -> VrfSeedCache {
        self.vrf_seeds.clone()
    }

    fn round_prevrandao(&self, round: Round) -> Option<B256> {
        if self.native_pipeline || round.view().get() <= 1 {
            Some(B256::ZERO)
        } else {
            self.vrf_seeds.get(round)
        }
    }

    fn beneficiary_for(&self, leader: &PublicKey) -> Address {
        self.participant_addresses
            .iter()
            .find(|(pk, _)| pk == leader)
            .map_or(Address::ZERO, |(_, addr)| *addr)
    }

    fn block_context(
        &self,
        height: u64,
        timestamp: u64,
        prevrandao: B256,
        leader: &PublicKey,
    ) -> BlockContext {
        let header = Header {
            number: height,
            timestamp,
            gas_limit: self.gas_limit,
            beneficiary: self.beneficiary_for(leader),
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        BlockContext::new(header, B256::ZERO, prevrandao)
    }

    async fn re_execute(
        &self,
        block: &Block,
        batches: D::Unmerkleized,
    ) -> Result<D::Merkleized, AppError> {
        if !D::accepts(block) {
            return Err(AppError::RootMismatch("storage layout"));
        }
        let context = self
            .block_context(
                block.height,
                block.timestamp,
                block.prevrandao,
                &block.context.leader,
            )
            .with_verification()
            .with_expected_module_state_root(block.module_state_root);
        let executed = Box::pin(D::execute(&self.executor, batches, &context, &block.txs)).await?;
        if executed.state_root != block.state_root {
            return Err(AppError::RootMismatch("state root"));
        }
        if executed.outcome.module_state_root != block.module_state_root {
            return Err(AppError::RootMismatch("module state root"));
        }
        if executed.db_targets != block.db_targets
            || executed.native_targets != block.native_targets
        {
            return Err(AppError::RootMismatch("db targets"));
        }
        if block.receipt_commitment.is_some_and(|expected| {
            receipt_commitment(self.gas_limit, &executed.outcome.receipts) != expected
        }) {
            return Err(AppError::RootMismatch("execution receipts"));
        }
        Ok(D::with_receipts(
            executed.batches,
            executed.outcome.receipts,
        ))
    }

    fn pending_tx_ids(blocks: &[Arc<Block>]) -> BTreeSet<TxId> {
        blocks
            .iter()
            .flat_map(|block| block.txs.iter().map(vera_domain::Tx::id))
            .collect()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

impl<S: FinalizedSink, D: ApplicationState> Application<Ctx> for StatefulVeraApp<S, D> {
    type SigningScheme = ConsensusScheme;
    type Context = ConsensusContext;
    type Block = Block;
    type Databases = D;
    type Captured = Vec<ExecutionReceipt>;
    type Provider = InMemoryMempool;
    type Input = ReshareInput;

    fn sync_targets(block: &Self::Block) -> D::SyncTargets {
        D::targets(block)
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn prepare(
        &mut self,
        context: (Ctx, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: D::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Handoff<Proposed<Self, Ctx>> {
        if !self.native_pipeline {
            return Handoff::Wait;
        }
        match self.propose(context, ancestry, batches, input).await {
            Some(proposed) => Handoff::Stage(proposed),
            None => Handoff::Wait,
        }
    }

    async fn propose(
        &mut self,
        context: (Ctx, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: D::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, Ctx>> {
        let start = Instant::now();
        let consensus_context = context.1;
        let parent = ancestry.next().await?.inner_shared();
        if !D::accepts(&parent) {
            return None;
        }
        let mut pending = vec![parent.clone()];
        let finalized_height = self.sink.finalized_height();
        while pending.len() < MAX_PENDING_ANCESTORS
            && pending
                .last()
                .is_some_and(|block| block.height > finalized_height)
        {
            match ancestry.next().await {
                Some(block) => pending.push(block.inner_shared()),
                None => break,
            }
        }
        let excluded = Self::pending_tx_ids(&pending);
        let mut txs = if self.native_pipeline {
            input
                .provider
                .build_block_wait(self.max_txs, &excluded, self.proposal_batch_wait)
                .await
        } else {
            input.provider.build_block(self.max_txs, &excluded)
        };
        if self.native_pipeline {
            txs.retain(|tx| {
                tx.bytes
                    .first()
                    .is_some_and(|byte| vera_domain::NativeTx::is_native_tx(*byte))
            });
        }

        let height = parent.height + 1;
        let timestamp = now_secs().max(parent.timestamp);
        let prevrandao = match self.round_prevrandao(consensus_context.round) {
            Some(seed) => seed,
            None => {
                warn!(round = ?consensus_context.round, "missing parent VRF seed");
                return None;
            }
        };
        let block_context =
            self.block_context(height, timestamp, prevrandao, &consensus_context.leader);
        let exec_start = Instant::now();
        let executed =
            match Box::pin(D::execute(&self.executor, batches, &block_context, &txs)).await {
                Ok(executed) => executed,
                Err(e) => {
                    warn!(height, txs = txs.len(), error = %e, "propose: execution failed");
                    return None;
                }
            };
        let exec_ms = exec_start.elapsed().as_millis();
        let txs = match &executed.outcome.executed_tx_indices {
            Some(indices) => indices.iter().map(|&i| txs[i].clone()).collect(),
            None => txs,
        };
        let block = Block {
            context: consensus_context,
            parent: parent.id(),
            height,
            timestamp,
            prevrandao,
            state_root: executed.state_root,
            module_state_root: executed.outcome.module_state_root,
            txs,
            payload: input.upstream.payload,
            native_targets: executed.native_targets,
            receipt_commitment: Some(receipt_commitment(
                self.gas_limit,
                &executed.outcome.receipts,
            )),
            db_targets: executed.db_targets,
        };
        if self.native_pipeline
            && block.txs.iter().any(|tx| {
                !tx.bytes
                    .first()
                    .is_some_and(|byte| vera_domain::NativeTx::is_native_tx(*byte))
            })
        {
            return None;
        }
        if !block.fits_wire_limits() {
            return None;
        }
        info!(
            block_digest = ?block.digest(),
            height,
            txs = block.txs.len(),
            snapshot_ms = 0u128,
            exec_ms,
            root_ms = 0u128,
            total_ms = start.elapsed().as_millis(),
            "built block"
        );
        self.sink.proposed(&block);
        Some(Proposed {
            block,
            merkleized: D::with_receipts(executed.batches, executed.outcome.receipts),
        })
    }

    async fn verify(
        &mut self,
        context: (Ctx, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: D::Unmerkleized,
    ) -> Option<D::Merkleized> {
        let start = Instant::now();
        let block = ancestry.next().await?;
        let digest = block.digest();
        let block = block.inner_shared();
        if !block.fits_wire_limits() {
            return None;
        }
        let parent = ancestry.next().await?.inner_shared();
        if !D::accepts(&parent) {
            return None;
        }
        if block.context != context.1 {
            warn!(?digest, "block consensus context mismatch");
            return None;
        }
        let expected_prevrandao = match self.round_prevrandao(context.1.round) {
            Some(seed) => seed,
            None => {
                warn!(round = ?context.1.round, "missing parent VRF seed");
                return None;
            }
        };
        if block.prevrandao != expected_prevrandao {
            warn!(
                ?digest,
                expected = ?expected_prevrandao,
                actual = ?block.prevrandao,
                "block prevrandao does not match parent VRF seed"
            );
            return None;
        }
        if block.timestamp < parent.timestamp {
            warn!(
                ?digest,
                block_ts = block.timestamp,
                parent_ts = parent.timestamp,
                "block timestamp before parent"
            );
            return None;
        }
        if block.timestamp > now_secs() + MAX_CLOCK_DRIFT_SECS {
            warn!(
                ?digest,
                block_ts = block.timestamp,
                "block timestamp too far in future"
            );
            return None;
        }
        match self.re_execute(&block, batches).await {
            Ok(merkleized) => {
                info!(
                    ?digest,
                    height = block.height,
                    txs = block.txs.len(),
                    snapshot_ms = 0u128,
                    exec_ms = start.elapsed().as_millis(),
                    root_ms = 0u128,
                    total_ms = start.elapsed().as_millis(),
                    "verified block"
                );
                Some(merkleized)
            }
            Err(e) => {
                warn!(?digest, height = block.height, error = %e, "verification failed");
                None
            }
        }
    }

    async fn apply(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        batches: D::Unmerkleized,
    ) -> Option<D::Merkleized> {
        match self.re_execute(block, batches).await {
            Ok(merkleized) => Some(merkleized),
            Err(e) => {
                warn!(height = block.height, error = %e, "apply failed");
                None
            }
        }
    }

    async fn capture(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        batches: &D::Merkleized,
        _readers: D::Readers,
    ) -> Self::Captured {
        let receipts = D::receipts(batches);
        assert_eq!(
            block.receipt_commitment,
            Some(receipt_commitment(self.gas_limit, receipts)),
            "sealed execution receipts must match the selected block"
        );
        receipts.to_vec()
    }

    async fn finalized(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        _readers: D::Readers,
    ) {
        let ids: Vec<TxId> = block.txs.iter().map(vera_domain::Tx::id).collect();
        self.mempool.prune(&ids);
        self.sink.finalized(block, captured).await;
        self.vrf_seeds.finalized(block.context.round);
    }
}
