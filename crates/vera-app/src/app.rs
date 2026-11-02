//! The glue stateful application.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{ApplicationState, VrfSeedCache, ordered_state::OrderedState};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use commonware_consensus::types::{Round, View};
use commonware_consensus::{Handoff, marshal::ancestry::Ancestry};
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::{Application, Finality, Input, Proposed};
use commonware_runtime::Clock as _;
use futures::StreamExt as _;
use std::marker::PhantomData;
use tracing::{info, warn};
use vera_backend::Ctx;
use vera_consensus::{Mempool as _, TxId, components::InMemoryMempool};
use vera_domain::{Block, ConsensusContext, PublicKey};
use vera_executor::{BlockContext, ExecutionReceipt, VeraExecutor, receipt_commitment};

use crate::{AppError, ConsensusScheme, FinalizedSink, ReshareInput};

const MAX_CLOCK_DRIFT_SECS: u64 = 15;
const MAX_TIMESTAMP_STEP_SECS: u64 = 5;
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
    vrf_verifier: Option<ConsensusScheme>,
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
            vrf_verifier: None,
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

    /// Authenticate rotating-mode randomness against the deployment consensus key.
    #[must_use]
    pub fn with_consensus_key(mut self, key: vera_domain::ConsensusPublicKey) -> Self {
        self.vrf_verifier = Some(ConsensusScheme::certificate_verifier(
            vera_domain::LIGHT_BLOCK_NAMESPACE,
            key,
        ));
        self
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
        if !self.native_pipeline {
            return Handoff::Wait;
        }
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
        let timestamp = now_secs()
            .max(parent.timestamp)
            .min(parent.timestamp.saturating_add(MAX_TIMESTAMP_STEP_SECS));
        let randomness = if self.native_pipeline || consensus_context.round.view().get() <= 1 {
            None
        } else {
            match self.vrf_seeds.witness(consensus_context.round) {
                Some(seed) => Some(seed),
                None => {
                    warn!(round = ?consensus_context.round, "missing parent VRF seed");
                    return None;
                }
            }
        };
        let prevrandao = randomness
            .as_ref()
            .map_or(B256::ZERO, crate::vrf_cache::seed_digest);
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
            randomness,
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
        if self.native_pipeline
            && block.txs.iter().any(|tx| {
                !tx.bytes
                    .first()
                    .is_some_and(|byte| vera_domain::NativeTx::is_native_tx(*byte))
            })
        {
            warn!(?digest, "legacy transaction in native-only block");
            return None;
        }
        if finality == Finality::Finalized {
            return match self.re_execute(&block, batches).await {
                Ok(merkleized) => Some(merkleized),
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
        let round = context.1.round;
        if self.native_pipeline || round.view().get() <= 1 {
            if block.randomness.is_some() || block.prevrandao != B256::ZERO {
                return None;
            }
        } else {
            let Some(seed) = &block.randomness else {
                return None;
            };
            let previous = Round::new(round.epoch(), View::new(round.view().get() - 1));
            let verifier = self
                .vrf_verifier
                .as_ref()
                .expect("consensus randomness verifier not configured");
            if seed.round != previous
                || !seed.verify(verifier)
                || block.prevrandao != crate::vrf_cache::seed_digest(seed)
            {
                warn!(?digest, "invalid authenticated consensus randomness");
                return None;
            }
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
        if block.timestamp > parent.timestamp.saturating_add(MAX_TIMESTAMP_STEP_SECS) {
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
                vera_domain::StateRoot(alloy_primitives::B256::ZERO),
                vera_domain::DbTargets::default(),
                alloy_primitives::B256::ZERO,
            );
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
            let block_context = candidate.context.clone();
            let ancestry = ancestry::from_iter([candidate, genesis].map(|block| {
                let digest = block.digest();
                Digested::precomputed(block, digest)
            }));
            let mut app = StatefulVeraApp::<NoopSink, FailingState>::new(
                VeraExecutor::new(9001),
                crate::genesis_block(
                    vera_domain::StateRoot(alloy_primitives::B256::ZERO),
                    vera_domain::DbTargets::default(),
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
    fn pipelined_candidate_rejects_legacy_transaction_before_execution() {
        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let genesis = crate::genesis_block(
                vera_domain::StateRoot(alloy_primitives::B256::ZERO),
                vera_domain::DbTargets::default(),
                alloy_primitives::B256::ZERO,
            );
            for (bytes, native_pipeline, reject) in [
                (vec![0x02], true, true),
                (vec![], true, true),
                (vec![vera_domain::NATIVE_TX_TYPE], true, false),
                (vec![0x02], false, false),
            ] {
                let mut candidate = genesis.clone();
                candidate.height = 1;
                candidate.parent = genesis.id();
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
                )
                .with_native_pipeline(native_pipeline, std::time::Duration::ZERO);
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
                vera_domain::StateRoot(alloy_primitives::B256::ZERO),
                vera_domain::DbTargets::default(),
                alloy_primitives::B256::ZERO,
            );
            genesis.timestamp = now + 14;
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
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

    #[test]
    fn candidate_timestamp_rejects_excessive_parent_step() {
        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let mut genesis = crate::genesis_block(
                vera_domain::StateRoot(alloy_primitives::B256::ZERO),
                vera_domain::DbTargets::default(),
                alloy_primitives::B256::ZERO,
            );
            genesis.timestamp = super::now_secs();
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
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
    #[test]
    fn rotating_candidate_authenticates_seed_without_election_cache() {
        use commonware_codec::{Decode as _, Encode as _, EncodeSize as _};
        use commonware_consensus::{
            simplex::{scheme::bls12381_threshold::vrf::Seed, types::Subject},
            types::{Epoch, Round, View},
        };
        use commonware_cryptography::{
            Signer as _,
            bls12381::{
                dkg::feldman_desmedt,
                primitives::{sharing::Mode, variant::MinSig},
            },
            certificate::Scheme as _,
            ed25519,
        };
        use commonware_parallel::Sequential;
        use commonware_runtime::Supervisor as _;
        use commonware_utils::{N3f1, TestRng, non_empty, ordered::Set};

        let players = Set::from_iter_dedup([ed25519::PrivateKey::from_seed(17).public_key()]);
        let (output, shares) = feldman_desmedt::deal::<MinSig, _, N3f1>(
            TestRng::new(17),
            Mode::NonZeroCounter,
            players.clone(),
        )
        .unwrap();
        let key = *output.public().public();
        let share = shares
            .get_value(players.iter().next().unwrap())
            .unwrap()
            .clone();
        let scheme = super::ConsensusScheme::signer(
            vera_domain::LIGHT_BLOCK_NAMESPACE,
            players.clone(),
            output.public().clone(),
            share,
        )
        .unwrap();
        let previous = Round::new(Epoch::zero(), View::new(1));
        let vote = scheme
            .sign::<vera_domain::ConsensusDigest>(Subject::Nullify { round: previous })
            .unwrap();
        let certificate = scheme.assemble(non_empty![vote], &Sequential).unwrap();
        let seed = Seed::new(previous, certificate.get().unwrap().seed_signature);
        let proposal_round = Round::new(Epoch::zero(), View::new(2));
        let cache = crate::VrfSeedCache::default();
        cache.insert_seed(proposal_round, seed.clone());
        assert_eq!(cache.witness(proposal_round), Some(seed.clone()));
        cache.finalized(proposal_round);
        assert_eq!(cache.witness(proposal_round), Some(seed.clone()));
        cache.finalized(Round::new(Epoch::zero(), View::new(3)));
        assert!(cache.witness(proposal_round).is_none());
        let forged = Seed::new(Round::new(Epoch::zero(), View::new(2)), seed.signature);
        let (wrong_output, wrong_shares) = feldman_desmedt::deal::<MinSig, _, N3f1>(
            TestRng::new(99),
            Mode::NonZeroCounter,
            players.clone(),
        )
        .unwrap();
        let wrong_share = wrong_shares
            .get_value(players.iter().next().unwrap())
            .unwrap()
            .clone();
        let wrong_scheme = super::ConsensusScheme::signer(
            vera_domain::LIGHT_BLOCK_NAMESPACE,
            players,
            wrong_output.public().clone(),
            wrong_share,
        )
        .unwrap();
        let wrong_vote = wrong_scheme
            .sign::<vera_domain::ConsensusDigest>(Subject::Nullify { round: previous })
            .unwrap();
        let wrong_cert = wrong_scheme
            .assemble(non_empty![wrong_vote], &Sequential)
            .unwrap();
        let wrong_seed = Seed::new(previous, wrong_cert.get().unwrap().seed_signature);

        tokio::Runner::new(tokio::Config::default()).start(|context| async move {
            let genesis = crate::genesis_block(
                vera_domain::StateRoot(alloy_primitives::B256::ZERO),
                vera_domain::DbTargets::default(),
                alloy_primitives::B256::ZERO,
            );
            let mut candidate = genesis.clone();
            candidate.height = 1;
            candidate.parent = genesis.id();
            candidate.context.round = Round::new(Epoch::zero(), View::new(2));
            candidate.prevrandao = crate::vrf_cache::seed_digest(&seed);
            candidate.randomness = Some(seed.clone());
            assert_eq!(candidate.encode_size(), candidate.encode().len());
            candidate = Block::decode_cfg(
                candidate.encode(),
                &vera_domain::BlockCfg {
                    max_txs: 64,
                    tx: vera_domain::TxCfg {
                        max_tx_bytes: vera_domain::MAX_TX_BYTES,
                    },
                },
            )
            .unwrap();
            let mut app = StatefulVeraApp::<NoopSink, FailingState>::new(
                VeraExecutor::new(9001),
                genesis.clone(),
                InMemoryMempool::new(),
                NoopSink,
                64,
                30_000_000,
            )
            .with_consensus_key(key);
            for kind in 0..5 {
                let mut block = candidate.clone();
                match kind {
                    1 => block.randomness = None,
                    2 => block.randomness = Some(forged.clone()),
                    3 => block.prevrandao = alloy_primitives::B256::ZERO,
                    4 => {
                        block.prevrandao = crate::vrf_cache::seed_digest(&wrong_seed);
                        block.randomness = Some(wrong_seed.clone());
                    }
                    _ => {}
                }
                let block_context = block.context.clone();
                let ancestry = ancestry::from_iter([block, genesis.clone()].map(|block| {
                    let digest = block.digest();
                    Digested::precomputed(block, digest)
                }));
                let result = std::panic::AssertUnwindSafe(app.process(
                    (context.child("seed_test"), block_context),
                    ancestry,
                    (),
                    Finality::Candidate,
                ))
                .catch_unwind()
                .await;
                if kind == 0 {
                    assert!(
                        result.is_err(),
                        "valid witness should reach execution without a cached seed"
                    );
                } else {
                    assert!(
                        matches!(result, Ok(None)),
                        "invalid witness must be rejected"
                    );
                }
            }
        });
    }
}
