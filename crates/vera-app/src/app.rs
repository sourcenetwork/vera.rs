//! The glue stateful application.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{ApplicationState, ordered_state::OrderedState};
use commonware_consensus::{Handoff, marshal::ancestry::Ancestry};
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::{Application, Finality, Input, Proposed};
use commonware_runtime::Clock as _;
use futures::StreamExt as _;
use std::marker::PhantomData;
use tracing::{info, warn};
use vera_backend::Ctx;
use vera_consensus::{Mempool as _, TxId, components::InMemoryMempool};
use vera_domain::{Block, ConsensusContext, Tx};
use vera_executor::{BlockContext, ExecutionReceipt, VeraExecutor, receipt_commitment};

use crate::{AppError, ConsensusScheme, FinalizedSink, ReshareInput};

const MAX_CLOCK_DRIFT_SECS: u64 = 15;
/// Default limit on how far a block's timestamp may advance past its parent's.
pub const MAX_TIMESTAMP_STEP_SECS: u64 = 5;
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
    proposal_batch_wait: std::time::Duration,
    settled_batch_wait: Option<std::time::Duration>,
    timestamp_step: u64,
    term: crate::TermGuard,
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
            proposal_batch_wait: std::time::Duration::ZERO,
            settled_batch_wait: None,
            timestamp_step: MAX_TIMESTAMP_STEP_SECS,
            term: crate::TermGuard::default(),
        }
    }

    /// Propose in the term `term` holds and refuse a lower one above its cut.
    #[must_use]
    pub fn with_term(mut self, term: crate::TermGuard) -> Self {
        self.term = term;
        self
    }

    /// Whether `block` may follow `parent` in the terms this node accepts.
    fn admits_term(&self, block: &Block, parent: &Block) -> bool {
        vera_domain::term_extends(parent.term, block.term)
            && self.term.admits(block.height, block.term)
    }

    /// Wait up to `batch_wait` for requests before building a proposal.
    #[must_use]
    pub const fn with_proposal_batch_wait(mut self, batch_wait: std::time::Duration) -> Self {
        self.proposal_batch_wait = batch_wait;
        self
    }

    /// Collect requests for `wait` instead of the batch window when the parent is finalized.
    ///
    /// For a lone validator, a request that finds every block finalized has
    /// no block in flight to wait for, only requests sent with it.
    #[must_use]
    pub const fn with_settled_batch_wait(mut self, wait: Option<std::time::Duration>) -> Self {
        self.settled_batch_wait = wait;
        self
    }

    /// Limit how far a block's timestamp may advance past its parent's, in seconds.
    ///
    /// Every validator must use the same limit. A chain that finalizes less
    /// often than this, or resumes after a pause, falls behind the clock by
    /// the difference at every block.
    #[must_use]
    pub const fn with_timestamp_step(mut self, seconds: u64) -> Self {
        self.timestamp_step = seconds;
        self
    }

    const fn block_context(&self, height: u64, timestamp: u64) -> BlockContext {
        BlockContext::new(height, timestamp, self.gas_limit)
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
            .block_context(block.height, block.timestamp)
            .with_verification()
            .with_expected_module_state_root(block.module_state_root);
        let executed = Box::pin(D::execute(&self.executor, batches, &context, &block.txs)).await?;
        if executed.outcome.module_state_root != block.module_state_root {
            return Err(AppError::RootMismatch("module state root"));
        }
        if executed.native_targets != block.native_targets {
            return Err(AppError::RootMismatch("db targets"));
        }
        if receipt_commitment(self.gas_limit, &executed.outcome.receipts)
            != block.receipt_commitment
        {
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

fn require_validity_decision(error: &AppError) {
    assert!(
        !error.is_local_state_failure(),
        "local state failed while processing a candidate block: {error}"
    );
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
        self.propose(context, ancestry, batches, input)
            .await
            .map_or(Handoff::Wait, Handoff::Stage)
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
        // The actor processes finalization only between builds, so a proposer
        // that idles waits before its request reaches the actor, not here.
        let batch_wait = match self.settled_batch_wait {
            Some(wait) if parent.height <= finalized_height => wait,
            _ => self.proposal_batch_wait,
        };
        let txs = input
            .provider
            .build_block_wait(self.max_txs, &excluded, batch_wait)
            .await;

        let height = parent.height + 1;
        let term = self.term.term();
        if term < parent.term {
            warn!(
                height,
                term,
                parent_term = parent.term,
                "propose: the parent belongs to a later term"
            );
            return None;
        }
        // Hashing a block encodes it whole, so the parent is hashed once.
        let parent_id = parent.id();
        let ancestry = match parent.ancestry.extended(parent.height, &parent_id) {
            Ok(ancestry) => ancestry,
            Err(error) => {
                warn!(height, %error, "propose: the parent's ancestry cannot be extended");
                return None;
            }
        };
        let timestamp = now_secs()
            .max(parent.timestamp)
            .min(parent.timestamp.saturating_add(self.timestamp_step));
        let block_context = self.block_context(height, timestamp);
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
        let rejected: Vec<TxId> = executed
            .outcome
            .rejected_tx_indices
            .iter()
            .map(|&index| txs[index].id())
            .collect();
        if !rejected.is_empty() {
            self.mempool.prune(&rejected);
        }
        let txs = match &executed.outcome.executed_tx_indices {
            Some(indices) => indices.iter().map(|&i| txs[i].clone()).collect(),
            None => txs,
        };
        let block = Block {
            context: consensus_context,
            parent: parent_id,
            height,
            ancestry,
            timestamp,
            term,
            module_state_root: executed.outcome.module_state_root,
            txs,
            payload: input.upstream.payload,
            native_targets: executed.native_targets,
            receipt_commitment: receipt_commitment(self.gas_limit, &executed.outcome.receipts),
        };
        if !block.fits_wire_limits() {
            return None;
        }
        info!(
            block_digest = ?block.digest(),
            height,
            txs = block.txs.len(),
            exec_ms,
            total_ms = start.elapsed().as_millis(),
            "built block"
        );
        self.sink.proposed(&block);
        Some(Proposed {
            block,
            merkleized: D::with_receipts(executed.batches, executed.outcome.receipts),
        })
    }

    async fn process(
        &mut self,
        context: (Ctx, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        batches: D::Unmerkleized,
        finality: Finality,
    ) -> Option<D::Merkleized> {
        let start = Instant::now();
        let block = ancestry.next().await?;
        let digest = block.digest();
        let block = block.inner_shared();
        if !block.txs.iter().all(Tx::is_native) {
            warn!(
                ?digest,
                "block carries a transaction that is not a native request"
            );
            return None;
        }
        if finality == Finality::Finalized {
            if !self.term.admits_finalized(block.height, block.term) {
                warn!(
                    ?digest,
                    height = block.height,
                    term = block.term,
                    held_term = self.term.term(),
                    "finalized block of a lower term"
                );
                return None;
            }
            return match self.re_execute(&block, batches).await {
                Ok(merkleized) => {
                    self.term.observe(block.height, block.term);
                    Some(merkleized)
                }
                Err(error) => {
                    warn!(?digest, height = block.height, %error, "finalized block replay failed");
                    None
                }
            };
        }
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
        if !block.extends_ancestry(&parent) {
            warn!(
                ?digest,
                height = block.height,
                "block ancestry does not extend its parent's"
            );
            return None;
        }
        if !self.admits_term(&block, &parent) {
            warn!(
                ?digest,
                term = block.term,
                parent_term = parent.term,
                held_term = self.term.term(),
                "block of a lower term"
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
        if block.timestamp > parent.timestamp.saturating_add(self.timestamp_step) {
            warn!(
                ?digest,
                block_ts = block.timestamp,
                parent_ts = parent.timestamp,
                "block timestamp advances too far"
            );
            return None;
        }
        loop {
            let wait = block
                .timestamp
                .saturating_sub(now_secs().saturating_add(MAX_CLOCK_DRIFT_SECS));
            if wait == 0 {
                break;
            }
            context.0.sleep(std::time::Duration::from_secs(wait)).await;
        }
        let exec_start = Instant::now();
        match self.re_execute(&block, batches).await {
            Ok(merkleized) => {
                info!(
                    ?digest,
                    height = block.height,
                    txs = block.txs.len(),
                    exec_ms = exec_start.elapsed().as_millis(),
                    total_ms = start.elapsed().as_millis(),
                    "verified block"
                );
                Some(merkleized)
            }
            Err(e) => {
                require_validity_decision(&e);
                warn!(?digest, height = block.height, error = %e, "verification failed");
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
            receipt_commitment(self.gas_limit, receipts),
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
        self.term.observe(block.height, block.term);
        self.sink.finalized(block, captured).await;
    }
}

#[cfg(test)]
mod processing_failure_tests {
    use super::{StatefulVeraApp, require_validity_decision};
    use crate::{AppError, ApplicationState, NoopSink, StateExecution};
    use commonware_consensus::marshal::ancestry;
    use commonware_cryptography::{Digested, Digestible as _};
    use commonware_glue::stateful::{
        Application, Finality,
        db::{Barrier, DatabaseSet},
    };
    use commonware_runtime::{Runner as _, Supervisor as _, tokio};
    use futures::FutureExt as _;
    use vera_backend::Ctx;
    use vera_consensus::components::InMemoryMempool;
    use vera_domain::{Block, Tx};
    use vera_executor::{BlockContext, ExecutionReceipt, VeraExecutor};

    #[derive(Clone)]
    struct FailingState;

    impl DatabaseSet<Ctx> for FailingState {
        type Unmerkleized = ();
        type Merkleized = ();
        type Readers = ();
        type Config = ();
        type SyncTargets = ();

        async fn init(_: Ctx, _: (), _: Option<()>) -> Self {
            Self
        }
        fn initial_sync_targets() {}
        async fn new_batches(&self) {}
        fn fork_batches(_: &()) {}
        fn matches_sync_targets(_: &(), _: &()) -> bool {
            true
        }
        fn readers(&self) {}
        async fn apply(&self, _: ()) {}
        async fn finalize(&self) -> Barrier {
            panic!("not used by this test")
        }
        async fn prune(&self, _: &()) {}
        async fn committed_targets(&self) {}
    }

    impl ApplicationState for FailingState {
        fn accepts(_: &Block) -> bool {
            true
        }
        fn targets(_: &Block) {}
        fn with_receipts(_: (), _: Vec<ExecutionReceipt>) {}
        fn receipts(_: &()) -> &[ExecutionReceipt] {
            &[]
        }
        async fn execute(
            _: &VeraExecutor,
            _: (),
            _: &BlockContext,
            _: &[Tx],
        ) -> Result<StateExecution<Self>, AppError> {
            Err(AppError::State(vera_backend::BackendError::Storage(
                "injected read failure".into(),
            )))
        }
    }

    #[test]
    fn local_storage_failure_stops_processing_instead_of_rejecting_the_block() {
        let local = AppError::State(vera_backend::BackendError::Storage("disk error".into()));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                require_validity_decision(&local);
            }))
            .is_err()
        );
        require_validity_decision(&AppError::RootMismatch("state root"));
    }

    #[test]
    fn candidate_processing_fails_stopped_on_a_storage_error() {
        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let genesis = crate::genesis_block(
                alloy_primitives::B256::ZERO,
                Default::default(),
                alloy_primitives::B256::ZERO,
            );
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
            candidate.ancestry = genesis.ancestry.extended(0, &genesis.id()).unwrap();
            let block_context = candidate.context.clone();
            let ancestry = ancestry::from_iter([candidate, genesis].map(|block| {
                let digest = block.digest();
                Digested::precomputed(block, digest)
            }));
            let mut app = StatefulVeraApp::<NoopSink, FailingState>::new(
                VeraExecutor::new(9001),
                crate::genesis_block(
                    alloy_primitives::B256::ZERO,
                    Default::default(),
                    alloy_primitives::B256::ZERO,
                ),
                InMemoryMempool::new(),
                NoopSink,
                64,
                30_000_000,
            );
            let result = std::panic::AssertUnwindSafe(app.process(
                (context, block_context),
                ancestry,
                (),
                Finality::Candidate,
            ))
            .catch_unwind()
            .await;
            assert!(
                result.is_err(),
                "a local failure must not return an invalid-block decision"
            );
        });
    }

    #[test]
    fn candidate_with_a_non_native_transaction_is_rejected_before_execution() {
        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let genesis = crate::genesis_block(
                alloy_primitives::B256::ZERO,
                Default::default(),
                alloy_primitives::B256::ZERO,
            );
            for (bytes, reject) in [
                (vec![0x02], true),
                (vec![], true),
                (vec![vera_domain::NATIVE_TX_TYPE], false),
            ] {
                let mut candidate = genesis.clone();
                candidate.height = 1;
                candidate.parent = genesis.id();
                candidate.ancestry = genesis.ancestry.extended(0, &genesis.id()).unwrap();
                candidate.txs.push(Tx::new(bytes.into()));
                let block_context = candidate.context.clone();
                let ancestry = ancestry::from_iter([candidate, genesis.clone()].map(|block| {
                    let digest = block.digest();
                    Digested::precomputed(block, digest)
                }));
                let mut app = StatefulVeraApp::<NoopSink, FailingState>::new(
                    VeraExecutor::new(9001),
                    genesis.clone(),
                    InMemoryMempool::new(),
                    NoopSink,
                    64,
                    30_000_000,
                );
                let result = std::panic::AssertUnwindSafe(app.process(
                    (context.child("block_validation"), block_context),
                    ancestry,
                    (),
                    Finality::Candidate,
                ))
                .catch_unwind()
                .await;
                if reject {
                    assert!(
                        matches!(result, Ok(None)),
                        "block must be rejected before execution"
                    );
                } else {
                    assert!(result.is_err(), "block must reach execution");
                }
            }
        });
    }

    #[test]
    fn candidate_timestamp_waits_for_local_clock() {
        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let now = super::now_secs();
            let mut genesis = crate::genesis_block(
                alloy_primitives::B256::ZERO,
                Default::default(),
                alloy_primitives::B256::ZERO,
            );
            genesis.timestamp = now + 14;
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
            candidate.ancestry = genesis.ancestry.extended(0, &genesis.id()).unwrap();
            candidate.timestamp = now + 18;
            let block_context = candidate.context.clone();
            let ancestry = ancestry::from_iter([candidate, genesis.clone()].map(|block| {
                let digest = block.digest();
                Digested::precomputed(block, digest)
            }));
            let mut app = StatefulVeraApp::<NoopSink, FailingState>::new(
                VeraExecutor::new(9001),
                genesis,
                InMemoryMempool::new(),
                NoopSink,
                64,
                30_000_000,
            );
            let processing = std::panic::AssertUnwindSafe(app.process(
                (context, block_context),
                ancestry,
                (),
                Finality::Candidate,
            ))
            .catch_unwind();
            ::tokio::pin!(processing);
            assert!(
                ::tokio::time::timeout(std::time::Duration::from_millis(100), &mut processing)
                    .await
                    .is_err()
            );
            let result = ::tokio::time::timeout(std::time::Duration::from_secs(5), processing)
                .await
                .expect("clock wait did not finish");
            assert!(
                result.is_err(),
                "processing must reach the injected local failure"
            );
        });
    }

    /// Processes a candidate of `term` at height 1 on a parent of `parent_term`.
    /// A refused block returns `None`; an admitted one reaches the injected failure.
    fn admitted(parent_term: u64, term: u64, held: Option<(u64, u64)>) -> bool {
        processed(parent_term, term, held, |_| {})
    }

    /// As [`admitted`], with `alter` applied to the candidate first.
    fn processed(
        parent_term: u64,
        term: u64,
        held: Option<(u64, u64)>,
        alter: impl FnOnce(&mut Block) + Send + 'static,
    ) -> bool {
        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let mut genesis = crate::genesis_block(
                alloy_primitives::B256::ZERO,
                Default::default(),
                alloy_primitives::B256::ZERO,
            );
            genesis.timestamp = super::now_secs();
            genesis.term = parent_term;
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
            candidate.ancestry = genesis.ancestry.extended(0, &genesis.id()).unwrap();
            candidate.term = term;
            alter(&mut candidate);
            let block_context = candidate.context.clone();
            let ancestry = ancestry::from_iter([candidate, genesis.clone()].map(|block| {
                let digest = block.digest();
                Digested::precomputed(block, digest)
            }));
            let guard = crate::TermGuard::default();
            if let Some((term, cut)) = held {
                guard.raise(term, cut);
            }
            let mut app = StatefulVeraApp::<NoopSink, FailingState>::new(
                VeraExecutor::new(9001),
                genesis,
                InMemoryMempool::new(),
                NoopSink,
                64,
                30_000_000,
            )
            .with_term(guard);
            let result = std::panic::AssertUnwindSafe(app.process(
                (context, block_context),
                ancestry,
                (),
                Finality::Candidate,
            ))
            .catch_unwind()
            .await;
            assert!(matches!(result, Ok(None) | Err(_)));
            result.is_err()
        })
    }

    #[test]
    fn a_candidate_whose_ancestry_does_not_extend_its_parents_is_refused() {
        assert!(processed(0, 0, None, |_| {}));
        assert!(!processed(0, 0, None, |candidate| {
            candidate.ancestry = vera_domain::testing::ancestry(1);
        }));
    }

    #[test]
    fn a_candidate_of_a_lower_term_than_its_parent_is_refused() {
        assert!(admitted(2, 2, None));
        assert!(admitted(2, 3, None));
        assert!(!admitted(2, 1, None));
    }

    #[test]
    fn a_candidate_below_the_held_term_is_refused_above_the_cut() {
        assert!(!admitted(0, 1, Some((2, 0))));
        assert!(admitted(0, 2, Some((2, 0))));
        assert!(admitted(0, 1, Some((2, 1))));
    }

    #[test]
    fn candidate_timestamp_rejects_excessive_parent_step() {
        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let mut genesis = crate::genesis_block(
                alloy_primitives::B256::ZERO,
                Default::default(),
                alloy_primitives::B256::ZERO,
            );
            genesis.timestamp = super::now_secs();
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
            candidate.ancestry = genesis.ancestry.extended(0, &genesis.id()).unwrap();
            candidate.timestamp = genesis.timestamp + super::MAX_TIMESTAMP_STEP_SECS + 1;
            let block_context = candidate.context.clone();
            let ancestry = ancestry::from_iter([candidate, genesis.clone()].map(|block| {
                let digest = block.digest();
                Digested::precomputed(block, digest)
            }));
            let mut app = StatefulVeraApp::<NoopSink, FailingState>::new(
                VeraExecutor::new(9001),
                genesis,
                InMemoryMempool::new(),
                NoopSink,
                64,
                30_000_000,
            );
            let result = std::panic::AssertUnwindSafe(app.process(
                (context, block_context),
                ancestry,
                (),
                Finality::Candidate,
            ))
            .catch_unwind()
            .await;
            assert!(matches!(result, Ok(None)));
        });
    }
}
