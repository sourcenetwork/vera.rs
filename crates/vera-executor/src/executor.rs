//! VeraExecutor — EVM executor with vera precompiles (ACP, Bulletin, Vera)
//! and native BLS transaction support.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, RwLock};

use crate::{
    BlockContext, BlockExecutor, ExecutionConfig, ExecutionError, ExecutionOutcome,
    ExecutionReceipt, ModuleSnapshot, StateDbAdapter, build_receipt, decode_evm_tx,
    extract_changes,
};
use alloy_primitives::{B256, Bytes, U256, keccak256};
use commonware_parallel::{Rayon, Sequential, Strategy};
use revm::{
    Context, ExecuteCommitEvm, InspectEvm, Journal, MainBuilder,
    context::{block::BlockEnv, result::ExecutionResult},
    context_interface::{ContextTr, JournalTr},
    database::State,
    precompile::PrecompileError,
    primitives::hardfork::SpecId,
};
use tracing::warn;
#[cfg(test)]
use vera_crypto::bls;
use vera_domain::NativeTx;
use vera_modules::acp::AcpModule;
use vera_modules::bulletin::BulletinModule;
use vera_modules::module_state::{ModuleState, SharedModuleState, state_root_from_jmt};
use vera_modules::native_account::NativeNonceStore;
use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};
use vera_modules::vera::VeraModule;
use vera_state::ModuleStateTree;
use vera_traits::StateDb;

use crate::precompiles::{
    ACP_ADDRESS, BULLETIN_ADDRESS, VALIDATOR_REGISTRY_ADDRESS, VERA_ADDRESS, VeraPrecompiles,
    dispatch_to_module,
};

/// Gas budget for native BLS transactions dispatched to modules.
const NATIVE_TX_GAS_LIMIT: u64 = 1_000_000;

mod gas_budget;
mod native_authentication;
mod recovery;

use gas_budget::BlockGasBudget;
use native_authentication::AuthenticatedNativeTx;

/// Per-module JMT-backed state trees: [acp, bulletin, vera, nonces].
pub type ModuleTrees = [Arc<Mutex<ModuleStateTree>>; 4];

/// Block executor with vera precompiles (ACP, Bulletin, Vera).
///
/// Processes both EVM transactions (secp256k1) and native BLS transactions
/// (BLS12-381) in block order. The first byte of each transaction determines
/// the path: `0x45` → native BLS, anything else → REVM.
///
/// Shared module state serves committed queries. Consensus execution supplies
/// an explicit parent snapshot and receives its post-execution state.
#[derive(Clone, Debug)]
pub struct VeraExecutor {
    config: ExecutionConfig,
    modules: SharedModuleState,
    module_trees: Option<ModuleTrees>,
    native_verification: Option<Rayon>,
    commit_lock: Arc<Mutex<()>>,
    #[cfg(feature = "fault-injection")]
    crash_marker: Option<std::path::PathBuf>,
}

impl VeraExecutor {
    /// The EVM specification revision used for execution.
    pub const fn spec_id(&self) -> SpecId {
        self.config.spec_id
    }

    /// Configure a one-shot process crash marker for persistence tests.
    #[cfg(feature = "fault-injection")]
    #[must_use]
    pub fn with_crash_marker(mut self, path: std::path::PathBuf) -> Self {
        self.crash_marker = Some(path);
        self
    }

    /// Abort at a selected module boundary in fault-injection builds.
    #[cfg(feature = "fault-injection")]
    pub fn after_module_commit(&self, height: u64, index: usize) {
        if let Some(marker) = &self.crash_marker {
            crate::faults::after_module_commit(marker, height, index);
        }
    }
    /// Create a new vera executor.
    pub fn new(chain_id: u64) -> Self {
        Self {
            config: ExecutionConfig::new(chain_id),
            modules: Arc::new(RwLock::new(ModuleState::default())),
            module_trees: None,
            native_verification: None,
            commit_lock: Arc::default(),
            #[cfg(feature = "fault-injection")]
            crash_marker: None,
        }
    }

    /// Create a new vera executor with full configuration.
    pub fn with_config(config: ExecutionConfig) -> Self {
        Self {
            config,
            modules: Arc::new(RwLock::new(ModuleState::default())),
            module_trees: None,
            native_verification: None,
            commit_lock: Arc::default(),
            #[cfg(feature = "fault-injection")]
            crash_marker: None,
        }
    }

    /// Share a bounded worker pool for independent native signature checks.
    /// Nonce checks and module execution remain in transaction order.
    #[must_use]
    pub fn with_native_verification_strategy(mut self, strategy: Rayon) -> Self {
        self.native_verification = Some(strategy);
        self
    }

    /// Attach JMT-backed module state trees for authenticated state roots.
    #[must_use]
    pub fn with_module_trees(mut self, trees: ModuleTrees) -> Self {
        self.module_trees = Some(trees);
        self
    }

    /// Select future consensus rosters at the configured epoch boundaries.
    #[must_use]
    pub const fn with_membership_epochs(
        mut self,
        length: std::num::NonZeroU64,
        term_length: std::num::NonZeroU64,
    ) -> Self {
        self.config.membership_epoch_length = Some(length);
        self.config.membership_term_length = term_length;
        self
    }

    /// Bind administrative execution to the deployment genesis record.
    #[must_use]
    pub const fn with_genesis_id(mut self, genesis_id: [u8; 32]) -> Self {
        self.config.genesis_id = genesis_id;
        self
    }

    /// Get the chain ID.
    pub const fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Get the execution configuration.
    pub const fn config(&self) -> &ExecutionConfig {
        &self.config
    }

    /// Get the shared module state.
    pub const fn modules(&self) -> &SharedModuleState {
        &self.modules
    }

    /// Get the JMT-backed module state trees, if attached.
    pub const fn module_trees(&self) -> Option<&ModuleTrees> {
        self.module_trees.as_ref()
    }

    /// Install module state loaded at startup or selected by finalization.
    pub fn set_base_modules(&self, modules: ModuleState) {
        *self.modules.write().unwrap() = modules;
    }

    /// Capture module values and tree views from the same committed revision.
    pub fn snapshot(&self) -> Result<ModuleSnapshot, ExecutionError> {
        let _guard = self.commit_lock.lock().unwrap();
        let trees = self
            .module_trees
            .as_ref()
            .map(|trees| {
                let snapshots = trees
                    .iter()
                    .map(|tree| tree.lock().unwrap().snapshot())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?;
                Ok::<_, ExecutionError>(snapshots.try_into().expect("four module trees"))
            })
            .transpose()?;
        Ok(ModuleSnapshot {
            modules: self.modules.read().unwrap().clone(),
            trees,
        })
    }

    /// Persist selected tree updates before replacing the shared module values.
    pub fn commit_snapshot(
        &self,
        height: u64,
        snapshot: ModuleSnapshot,
    ) -> Result<(), ExecutionError> {
        let _guard = self.commit_lock.lock().unwrap();
        match (&self.module_trees, &snapshot.trees) {
            (Some(trees), Some(snapshots)) => {
                #[cfg(feature = "fault-injection")]
                let changed = trees.iter().zip(snapshots).any(|(tree, snapshot)| {
                    tree.lock().unwrap().root().expect("read module root") != snapshot.root()
                });
                for (index, (tree, snapshot)) in trees.iter().zip(snapshots).enumerate() {
                    tree.lock()
                        .unwrap()
                        .commit_prepared(height, snapshot)
                        .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?;
                    #[cfg(feature = "fault-injection")]
                    if changed && let Some(marker) = &self.crash_marker {
                        crate::faults::after_module_commit(marker, height, index);
                    }
                    #[cfg(not(feature = "fault-injection"))]
                    let _ = index;
                }
            }
            (None, None) => {}
            _ => {
                return Err(ExecutionError::ModuleTree(
                    "module snapshot has incompatible trees".into(),
                ));
            }
        }
        self.set_base_modules(snapshot.modules);
        Ok(())
    }

    /// Execute a native BLS transaction: verify signature, derive DID, dispatch to module.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn execute_native_tx<CTX: ContextTr>(
        &self,
        tx_bytes: &[u8],
        block_ctx: &BlockExecCtx,
        acp: &mut AcpModule,
        bulletin: &mut BulletinModule,
        vera: &mut VeraModule,
        nonce_store: &mut NativeNonceStore,
        journal: &mut CTX,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        self.execute_authenticated_native_tx(
            self.authenticate_native_tx(tx_bytes)?,
            block_ctx,
            acp,
            bulletin,
            vera,
            nonce_store,
            journal,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_authenticated_native_tx<CTX: ContextTr>(
        &self,
        authenticated: AuthenticatedNativeTx,
        block_ctx: &BlockExecCtx,
        acp: &mut AcpModule,
        bulletin: &mut BulletinModule,
        vera: &mut VeraModule,
        nonce_store: &mut NativeNonceStore,
        journal: &mut CTX,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        let AuthenticatedNativeTx {
            native_tx,
            signer_did,
        } = authenticated;
        nonce_store
            .check_and_increment(&signer_did, native_tx.nonce)
            .map_err(|e| match e {
                vera_modules::native_account::NonceError::Mismatch { did, expected, got } => {
                    ExecutionError::NonceMismatch { did, expected, got }
                }
                vera_modules::native_account::NonceError::Overflow(did) => {
                    ExecutionError::InvalidTx(format!("nonce overflow for {did}"))
                }
                vera_modules::native_account::NonceError::Malformed(did) => {
                    ExecutionError::InvalidTx(format!("stored nonce for {did} is malformed"))
                }
            })?;

        let tx_hash = native_tx.tx_id().0;
        let tx_ctx = TxExecCtx {
            sequence: native_tx.nonce,
            tx_hash: tx_hash.to_vec(),
            signer: signer_did,
        };

        let before = (acp.clone(), bulletin.clone(), vera.clone());
        let checkpoint = journal.journal_mut().checkpoint();
        let mut dispatch_result = catch_unwind(AssertUnwindSafe(|| {
            if native_tx.target == VALIDATOR_REGISTRY_ADDRESS {
                journal
                    .journal_mut()
                    .load_account(VALIDATOR_REGISTRY_ADDRESS)
                    .map_err(|error| {
                        PrecompileError::Fatal(format!("membership account read failed: {error:?}"))
                    })?;
                journal
                    .journal_mut()
                    .touch_account(VALIDATOR_REGISTRY_ADDRESS);
                return crate::precompiles::validator_registry::dispatch_with_journal(
                    journal,
                    acp,
                    vera,
                    self.config.max_active_members(),
                    &tx_ctx,
                    &native_tx.calldata,
                    NATIVE_TX_GAS_LIMIT,
                );
            }
            dispatch_to_module(
                acp,
                bulletin,
                vera,
                native_tx.target,
                &native_tx.calldata,
                block_ctx,
                &tx_ctx,
                NATIVE_TX_GAS_LIMIT,
            )
            .expect("target validated above")
        }));

        if matches!(&dispatch_result, Ok(Ok(result)) if !result.precompile.reverted)
            && !(acp.store().changes_fit_native_bounds(before.0.store())
                && bulletin.store().changes_fit_native_bounds(before.1.store())
                && vera.store().changes_fit_native_bounds(before.2.store()))
        {
            dispatch_result = Ok(Err(PrecompileError::Other(
                "module record exceeds native storage bounds".into(),
            )));
        }

        if !matches!(&dispatch_result, Ok(Ok(result)) if !result.precompile.reverted) {
            (*acp, *bulletin, *vera) = before;
            journal.journal_mut().checkpoint_revert(checkpoint);
        } else {
            journal.journal_mut().checkpoint_commit();
        }

        let failed_receipt = || {
            ExecutionReceipt::new(
                tx_hash,
                false,
                NATIVE_TX_GAS_LIMIT,
                0, // cumulative gas set by caller
                vec![],
                None,
            )
        };

        match dispatch_result {
            Ok(Ok(result)) if !result.precompile.reverted => Ok(ExecutionReceipt::new(
                tx_hash,
                true,
                result.precompile.gas_used,
                0, // cumulative gas set by caller
                result.logs,
                None,
            )),
            Ok(Ok(_)) => Ok(failed_receipt()),
            Ok(Err(PrecompileError::Fatal(message))) => Err(ExecutionError::TxExecution(message)),
            Ok(Err(_)) => Ok(failed_receipt()),
            Err(_) => {
                warn!(%tx_hash, "native tx module panicked");
                Ok(failed_receipt())
            }
        }
    }

    /// Run end-of-block hooks for modules that need per-block maintenance.
    fn run_end_block_hooks(
        modules: &mut ModuleState,
        block_ctx: &BlockExecCtx,
    ) -> Result<(), ExecutionError> {
        modules
            .acp
            .end_blocker(block_ctx)
            .map_err(|error| ExecutionError::BlockValidation(format!("ACP lifecycle: {error}")))?;
        modules
            .vera
            .check_and_update_expired_tokens(block_ctx)
            .map_err(|error| ExecutionError::BlockValidation(format!("Vera lifecycle: {error}")))?;
        Ok(())
    }
}

impl VeraExecutor {
    /// Execute against an owned parent snapshot without replacing query state.
    pub fn execute_with_modules<S: StateDb>(
        &self,
        state: &S,
        context: &BlockContext,
        txs: &[Bytes],
        parent: ModuleSnapshot,
    ) -> Result<(ExecutionOutcome, ModuleSnapshot), ExecutionError> {
        let ModuleSnapshot {
            modules: base_modules,
            trees: mut snapshots,
        } = parent;
        let mut modules = base_modules.clone();

        let block_ctx = BlockExecCtx {
            genesis_id: self.config.genesis_id,
            deployment_id: self.config.chain_id,
            timestamp: Timestamp {
                seconds: context.header.timestamp,
                block_height: context.header.number,
            },
        };

        let mut outcome = ExecutionOutcome::new();
        let mut gas_budget = BlockGasBudget::new(context.header.gas_limit);
        let building = !context.is_verification;
        let mut executed_indices: Vec<usize> = Vec::new();

        let adapter = StateDbAdapter::new(state.clone());
        let db = State::builder().with_database_ref(adapter).build();

        type Db<S> = State<revm::database::WrapDatabaseRef<StateDbAdapter<S>>>;
        let ctx: Context<BlockEnv, _, _, Db<S>, Journal<Db<S>>, ()> =
            Context::new(db, self.config.spec_id);
        let mut ctx = ctx
            .modify_cfg_chained(|cfg| {
                cfg.chain_id = self.config.chain_id;
            })
            .modify_block_chained(|blk: &mut BlockEnv| {
                blk.number = U256::from(context.header.number);
                blk.timestamp = U256::from(context.header.timestamp);
                blk.beneficiary = context.header.beneficiary;
                blk.gas_limit = context.header.gas_limit;
                blk.basefee = context.header.base_fee_per_gas.unwrap_or_default();
                blk.prevrandao = Some(context.prevrandao);
            });

        let native_started = tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG)
            .then(std::time::Instant::now);
        let native = txs.iter().enumerate().filter(|(_, bytes)| {
            bytes
                .first()
                .is_some_and(|byte| NativeTx::is_native_tx(*byte))
        });
        let authenticate = |(i, bytes): (usize, &Bytes)| (i, self.authenticate_native_tx(bytes));
        // Retain errors in order: an earlier nonce or dispatch failure must win
        // over a later authentication failure during proposal verification.
        let authenticated = match &self.native_verification {
            Some(strategy) => strategy.map_collect_vec(native, authenticate),
            None => Sequential.map_collect_vec(native, authenticate),
        };
        let authentication_elapsed = native_started.map(|started| started.elapsed());
        let native_count = authenticated.len();
        for (i, authenticated) in authenticated {
            if !gas_budget.admit(NATIVE_TX_GAS_LIMIT, building)? {
                continue;
            }
            let receipt = match authenticated.and_then(|authenticated| {
                self.execute_authenticated_native_tx(
                    authenticated,
                    &block_ctx,
                    &mut modules.acp,
                    &mut modules.bulletin,
                    &mut modules.vera,
                    &mut modules.nonces,
                    &mut ctx,
                )
            }) {
                Ok(r) => r,
                Err(error @ ExecutionError::TxExecution(_)) => return Err(error),
                Err(e) if building => {
                    let tx_hash = keccak256(&txs[i]);
                    warn!(%tx_hash, ?e, "skipping native tx");
                    continue;
                }
                Err(e) => return Err(e),
            };

            gas_budget.charge(NATIVE_TX_GAS_LIMIT, receipt.gas_used)?;
            let journaled = ctx.journal_mut().finalize();
            outcome.changes.merge(extract_changes(&journaled));
            // Native module storage is retained even when its account has no balance or code.
            for (address, account) in journaled {
                if account.is_touched() {
                    let storage = account
                        .storage
                        .into_iter()
                        .map(|(slot, value)| (slot, value.into()))
                        .collect();
                    ctx.journal_mut()
                        .db_mut()
                        .cache
                        .accounts
                        .get_mut(&address)
                        .expect("journaled account was loaded into the proposal cache")
                        .change(account.info, storage);
                }
            }

            executed_indices.push(i);
            let mut receipt = receipt;
            receipt.receipt.cumulative_gas_used = gas_budget.used();
            outcome.receipts.push(receipt);
        }

        if let Some((started, authentication)) = native_started.zip(authentication_elapsed) {
            tracing::debug!(target: "vera_diagnostics", height = context.header.number,
                native_count, authentication_us = authentication.as_micros(),
                dispatch_us = (started.elapsed() - authentication).as_micros(),
                "native execution stages");
        }

        let precompiles = VeraPrecompiles::with_modules(
            self.config.spec_id,
            modules.acp.clone(),
            modules.bulletin.clone(),
            modules.vera.clone(),
        )
        .with_genesis_id(self.config.genesis_id)
        .with_membership_limit(self.config.max_active_members());
        let mut evm = ctx
            .build_mainnet_with_inspector(precompiles.inspector())
            .with_precompiles(precompiles);

        for (i, tx_bytes) in txs.iter().enumerate() {
            if !tx_bytes.is_empty() && NativeTx::is_native_tx(tx_bytes[0]) {
                continue;
            }

            let tx_hash = keccak256(tx_bytes);

            let (tx_env, signer_did) = match decode_evm_tx(tx_bytes, self.config.chain_id) {
                Ok(r) => r,
                Err(ExecutionError::TxDecode(msg)) if building => {
                    warn!(%tx_hash, msg, "skipping tx: decode error");
                    continue;
                }
                Err(e) => return Err(e),
            };

            let tx_gas_limit = tx_env.gas_limit;
            if !gas_budget.admit(tx_gas_limit, building)? {
                continue;
            }

            evm.precompiles.set_tx_hash(tx_hash);
            evm.precompiles.set_signer_did(signer_did);

            evm.precompiles.begin_transaction();
            let execution = evm.inspect_tx(tx_env);
            evm.precompiles
                .finish_transaction(execution.as_ref().is_ok_and(|r| r.result.is_success()));
            let result_and_state = match execution {
                Ok(r) => r,
                Err(e) if building => {
                    warn!(%tx_hash, ?e, "skipping tx: execution error");
                    continue;
                }
                Err(e) => {
                    return Err(ExecutionError::TxExecution(format!("{e:?}")));
                }
            };

            match &result_and_state.result {
                ExecutionResult::Revert { output, .. } => {
                    let reason = String::from_utf8_lossy(output);
                    warn!(%tx_hash, %reason, "EVM tx reverted");
                }
                ExecutionResult::Halt { reason, .. } => {
                    warn!(%tx_hash, ?reason, "EVM tx halted");
                }
                ExecutionResult::Success { .. } => {}
            }

            executed_indices.push(i);

            let gas_used = result_and_state.result.gas_used();
            gas_budget.charge(tx_gas_limit, gas_used)?;

            let receipt = build_receipt(
                &result_and_state.result,
                tx_hash,
                gas_used,
                gas_budget.used(),
            );
            outcome.receipts.push(receipt);

            let changes = extract_changes(&result_and_state.state);
            // Advance the proposal cache without writing canonical state.
            evm.commit(result_and_state.state);
            outcome.changes.merge(changes);
        }

        let (acp, bulletin, vera) = evm.precompiles.take_modules();
        modules.acp = acp;
        modules.bulletin = bulletin;
        modules.vera = vera;

        if let Some(length) = self.config.membership_epoch_length {
            let height = context.header.number;
            if height % length.get() == length.get() - 1 {
                let epoch = (height / length.get()).checked_add(3).ok_or_else(|| {
                    ExecutionError::TxExecution("membership epoch overflow".into())
                })?;
                let keys =
                    crate::precompiles::validator_registry::active_consensus_keys(&mut evm.ctx)
                        .map_err(|error| ExecutionError::TxExecution(error.to_string()))?;
                modules
                    .vera
                    .record_consensus_roster(epoch, &keys)
                    .map_err(|error| ExecutionError::TxExecution(error.to_string()))?;
            }
        }

        Self::run_end_block_hooks(&mut modules, &block_ctx)?;

        if building {
            outcome.executed_tx_indices = Some(executed_indices);
        }

        outcome.gas_used = gas_budget.used();
        outcome.module_state_root = if context.receipt_only {
            B256::ZERO
        } else if let Some(ref trees) = self.module_trees {
            let stores = [
                modules.acp.store(),
                modules.bulletin.store(),
                modules.vera.store(),
                modules.nonces.store(),
            ];
            let changes = modules.diff_from(&base_modules);

            let parents = snapshots
                .as_mut()
                .ok_or_else(|| ExecutionError::ModuleTree("missing parent tree views".into()))?;
            for (i, (tree_lock, mut dirty)) in trees.iter().zip(changes).enumerate() {
                if i == 0 {
                    crate::relation_index::index_relationships(&parents[i], stores[i], &mut dirty)?;
                }
                parents[i] = tree_lock
                    .lock()
                    .unwrap()
                    .prepare(&parents[i], dirty)
                    .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?;
            }
            let jmt_roots = std::array::from_fn(|i| parents[i].root().0);
            state_root_from_jmt(&jmt_roots)
        } else {
            // Fallback for tests without JMT trees. Production code always
            // provides module_trees, so this path should never run in prod.
            modules.state_root()
        };

        Ok((
            outcome,
            ModuleSnapshot {
                modules,
                trees: snapshots,
            },
        ))
    }
}

impl<S: StateDb> BlockExecutor<S> for VeraExecutor {
    type Tx = Bytes;

    fn execute(
        &self,
        state: &S,
        context: &BlockContext,
        txs: &[Self::Tx],
    ) -> Result<ExecutionOutcome, ExecutionError> {
        let modules = self.snapshot()?;
        self.execute_with_modules(state, context, txs, modules)
            .map(|(outcome, _)| outcome)
    }

    fn validate_header(&self, header: &alloy_consensus::Header) -> Result<(), ExecutionError> {
        if header.gas_limit < self.config.gas_limit_bounds.min {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} below minimum {}",
                header.gas_limit, self.config.gas_limit_bounds.min
            )));
        }
        if header.gas_limit > self.config.gas_limit_bounds.max {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} above maximum {}",
                header.gas_limit, self.config.gas_limit_bounds.max
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, FixedBytes, KECCAK256_EMPTY};
    use vera_qmdb::ChangeSet;
    use vera_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct MockStateDb;

    impl StateDbRead for MockStateDb {
        async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
            Ok(0)
        }
        async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
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

    impl StateDbWrite for MockStateDb {
        async fn commit(&self, _changes: ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        async fn compute_root(&self, _changes: &ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        fn merge_changes(&self, _older: ChangeSet, newer: ChangeSet) -> ChangeSet {
            newer
        }
    }

    impl StateDb for MockStateDb {
        async fn state_root(&self) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
    }

    fn test_executor() -> VeraExecutor {
        VeraExecutor::new(9001)
    }

    fn test_block_ctx() -> BlockExecCtx {
        BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 1_700_000_000,
                block_height: 1,
            },
        }
    }

    fn test_journal()
    -> Context<BlockEnv, revm::context::TxEnv, revm::context::CfgEnv, revm::database::EmptyDB> {
        Context::new(
            revm::database::EmptyDB::default(),
            revm::primitives::hardfork::SpecId::default(),
        )
    }

    #[test]
    fn vera_executor_new() {
        let executor = test_executor();
        assert_eq!(executor.chain_id(), 9001);
    }

    #[test]
    fn vera_executor_execute_empty_block() {
        use alloy_consensus::Header;

        let executor = test_executor();
        let state = MockStateDb;
        let header = Header {
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        let context = BlockContext::new(header, B256::ZERO, B256::ZERO);
        let txs: Vec<Bytes> = vec![];
        let outcome = executor.execute(&state, &context, &txs).unwrap();
        assert_eq!(outcome.gas_used, 0);
        assert!(outcome.receipts.is_empty());
        assert_ne!(outcome.module_state_root, B256::ZERO);
    }

    #[test]
    fn expiry_batches_match_proposal_verification_and_leave_parent_unchanged() {
        use vera_modules::{kv_store::InMemoryKvStore, vera::keys::JWS_TOKEN_EXPIRY_PREFIX};

        let executor = test_executor();
        let mut modules = ModuleState::default();
        let issued = test_block_ctx();
        let issuer = identity::Did::new("did:key:issuer").unwrap();
        for id in 0..257 {
            modules
                .vera
                .store_or_update_jws_token(
                    &issued,
                    &id.to_string(),
                    &issuer,
                    "account",
                    issued.timestamp.clone(),
                    Timestamp {
                        seconds: issued.timestamp.seconds + 1,
                        block_height: 0,
                    },
                )
                .unwrap();
        }
        let mut parent = ModuleSnapshot {
            modules,
            trees: None,
        };
        let published = executor.snapshot().unwrap().modules.serialize_stores();
        for (offset, remaining) in [129, 1, 0].into_iter().enumerate() {
            let before = parent.modules.serialize_stores();
            let context = BlockContext::new(
                alloy_consensus::Header {
                    number: offset as u64 + 2,
                    timestamp: issued.timestamp.seconds + offset as u64 + 2,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: Some(0),
                    ..Default::default()
                },
                B256::ZERO,
                B256::ZERO,
            );
            let (proposed, next) = executor
                .execute_with_modules(&MockStateDb, &context, &[], parent.clone())
                .unwrap();
            let mut verification =
                context.with_expected_module_state_root(proposed.module_state_root);
            verification.is_verification = true;
            let (verified, verified_state) = executor
                .execute_with_modules(&MockStateDb, &verification, &[], parent.clone())
                .unwrap();
            assert_eq!(verified.module_state_root, proposed.module_state_root);
            assert_eq!(
                verified_state.modules.serialize_stores(),
                next.modules.serialize_stores()
            );
            assert_eq!(
                next.modules
                    .vera
                    .store()
                    .prefix_iter(JWS_TOKEN_EXPIRY_PREFIX)
                    .count(),
                remaining
            );
            assert!(proposed.receipts.is_empty());
            assert_eq!(parent.modules.serialize_stores(), before);
            assert_eq!(
                executor.snapshot().unwrap().modules.serialize_stores(),
                published
            );
            let stores = next
                .modules
                .serialize_stores()
                .map(|bytes| InMemoryKvStore::deserialize(&bytes).unwrap());
            parent = ModuleSnapshot {
                modules: ModuleState::from_stores(stores),
                trees: None,
            };
            parent.modules.vera.validate_restored_tokens().unwrap();
        }
    }

    #[test]
    fn lifecycle_corruption_rejects_proposals_and_preserves_parent() {
        use vera_modules::kv_store::{InMemoryKvStore, ModuleKvStore};
        for (partition, key, expected) in [
            (
                0,
                b"commitment_expiry/seconds/bad".to_vec(),
                "ACP lifecycle",
            ),
            (
                2,
                vera_modules::vera::keys::jws_token_key("bad"),
                "Vera lifecycle",
            ),
        ] {
            let executor = test_executor();
            let mut stores = std::array::from_fn(|_| InMemoryKvStore::default());
            stores[partition].put(&key, vec![0]);
            if partition == 2 {
                let index = [
                    vera_modules::vera::keys::JWS_TOKEN_EXPIRY_PREFIX,
                    &0u64.to_be_bytes(),
                    b"bad",
                ]
                .concat();
                stores[partition].put(&index, Vec::new());
            }
            let parent = ModuleSnapshot {
                modules: ModuleState::from_stores(stores),
                trees: None,
            };
            let before = parent.modules.serialize_stores();
            let published = executor.snapshot().unwrap().modules.serialize_stores();
            for verification in [false, true] {
                let mut context = BlockContext::new(
                    alloy_consensus::Header {
                        number: 1,
                        timestamp: 100,
                        gas_limit: 30_000_000,
                        base_fee_per_gas: Some(0),
                        ..Default::default()
                    },
                    B256::ZERO,
                    B256::ZERO,
                );
                context.is_verification = verification;
                let error = executor
                    .execute_with_modules(&MockStateDb, &context, &[], parent.clone())
                    .unwrap_err();
                assert!(error.to_string().contains(expected), "{error}");
                assert_eq!(parent.modules.serialize_stores(), before);
                assert_eq!(
                    executor.snapshot().unwrap().modules.serialize_stores(),
                    published
                );
            }
        }
    }

    #[test]
    fn vera_executor_validate_header() {
        let executor = test_executor();
        let header = alloy_consensus::Header {
            gas_limit: 30_000_000,
            ..Default::default()
        };
        assert!(
            <VeraExecutor as BlockExecutor<MockStateDb>>::validate_header(&executor, &header)
                .is_ok()
        );
    }

    #[test]
    fn parallel_native_authentication_preserves_execution_and_error_order() {
        let sequential = test_executor();
        let parallel = test_executor().with_native_verification_strategy(
            Rayon::new(std::num::NonZeroUsize::new(2).unwrap()).unwrap(),
        );
        let (sk, pk) = test_bls_keypair();
        let mut txs: Vec<Bytes> = (0..64)
            .map(|nonce| signed_native_tx(&sk, &pk, nonce).into())
            .collect();
        let mut invalid = NativeTx::decode_wire(&txs[3]).unwrap();
        invalid.calldata = Bytes::from_static(b"tampered");
        txs.insert(3, invalid.encode_wire().into());
        txs.insert(5, signed_native_tx(&sk, &pk, 0).into());
        txs.insert(7, Bytes::new());
        let context = BlockContext::new(
            alloy_consensus::Header {
                number: 1,
                gas_limit: 100_000_000,
                ..Default::default()
            },
            B256::ZERO,
            B256::ZERO,
        );
        let before = parallel.snapshot().unwrap().modules.state_root();
        let expected = sequential.execute(&MockStateDb, &context, &txs).unwrap();
        let actual = parallel.execute(&MockStateDb, &context, &txs).unwrap();
        assert_eq!(actual.receipts.len(), 64);
        assert_eq!(actual.executed_tx_indices, expected.executed_tx_indices);
        assert_eq!(actual.module_state_root, expected.module_state_root);
        assert_eq!(actual.gas_used, expected.gas_used);
        assert_eq!(
            serde_json::to_value(&actual.receipts).unwrap(),
            serde_json::to_value(&expected.receipts).unwrap()
        );
        let included: Vec<_> = actual
            .executed_tx_indices
            .unwrap()
            .into_iter()
            .map(|i| txs[i].clone())
            .collect();
        let verified = parallel
            .execute(
                &MockStateDb,
                &context.clone().with_verification(),
                &included,
            )
            .unwrap();
        assert_eq!(verified.module_state_root, actual.module_state_root);
        assert_eq!(
            serde_json::to_value(verified.receipts).unwrap(),
            serde_json::to_value(actual.receipts).unwrap()
        );
        assert!(matches!(
            parallel.execute(&MockStateDb, &context.clone().with_verification(), &txs),
            Err(ExecutionError::BlsVerification(_))
        ));
        txs.swap(3, 5);
        assert!(matches!(
            parallel.execute(&MockStateDb, &context.with_verification(), &txs),
            Err(ExecutionError::NonceMismatch { .. })
        ));
        assert_eq!(parallel.snapshot().unwrap().modules.state_root(), before);
    }

    #[test]
    fn native_tx_decode_error() {
        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        // 0x45 followed by garbage
        let bad_bytes = [0x45, 0xFF, 0xFF];
        let result = executor.execute_native_tx(
            &bad_bytes,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(result, Err(ExecutionError::TxDecode(_))));
    }

    #[test]
    fn native_tx_wrong_chain_id() {
        let tx = NativeTx {
            chain_id: 999,
            nonce: 0,
            bls_pubkey: FixedBytes::from([0xAA; 48]),
            target: ACP_ADDRESS,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0xBB; 96]),
        };
        let wire = tx.encode_wire();

        let executor = test_executor(); // chain_id = 9001
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        match result {
            Err(ExecutionError::ChainIdMismatch { expected, got }) => {
                assert_eq!(expected, 9001);
                assert_eq!(got, 999);
            }
            other => panic!("expected ChainIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn native_tx_invalid_bls_sig() {
        let tx = NativeTx {
            chain_id: 9001,
            nonce: 0,
            bls_pubkey: FixedBytes::from([0xFF; 48]), // not a valid G1 point
            target: ACP_ADDRESS,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0xBB; 96]),
        };
        let wire = tx.encode_wire();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(result, Err(ExecutionError::BlsVerification(_))));
    }

    #[test]
    fn native_tx_unknown_target() {
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();

        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        let bad_target = Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
        ]);

        let mut tx = NativeTx {
            chain_id: 9001,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: bad_target,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]), // placeholder
        };

        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);

        let wire = tx.encode_wire();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(
            result,
            Err(ExecutionError::UnknownNativeTarget(_))
        ));
        assert!(
            nonces.store().is_empty(),
            "invalid target must not consume a nonce"
        );
    }

    #[test]
    fn native_tx_building_mode_skips_invalid() {
        use alloy_consensus::Header;

        let executor = test_executor();
        let state = MockStateDb;
        let header = Header {
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        // Building mode (is_verification = false)
        let context = BlockContext::new(header, B256::ZERO, B256::ZERO);

        // Malformed native tx: 0x45 + garbage
        let bad_native = Bytes::from(vec![0x45, 0xFF, 0xFF]);
        let txs = vec![bad_native];

        let outcome = executor.execute(&state, &context, &txs).unwrap();
        // Invalid tx should be skipped
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.gas_used, 0);
        assert_eq!(outcome.executed_tx_indices, Some(vec![]));
    }

    #[test]
    fn empty_block_runs_end_hooks() {
        use alloy_consensus::Header;

        let executor = test_executor();
        let state = MockStateDb;
        let header = Header {
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        let context = BlockContext::new(header, B256::ZERO, B256::ZERO);
        let txs: Vec<Bytes> = vec![];

        // Should not panic — end-block hooks are no-ops
        let outcome = executor.execute(&state, &context, &txs).unwrap();
        assert_eq!(outcome.gas_used, 0);
    }

    #[test]
    fn native_tx_dispatches_to_module() {
        use alloy_sol_types::SolCall;
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;
        use vera_modules::acp::abi::IAcp;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();

        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        let calldata = IAcp::getParamsCall {}.abi_encode();

        let mut tx = NativeTx {
            chain_id: 9001,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: ACP_ADDRESS,
            calldata: Bytes::from(calldata),
            signature: FixedBytes::from([0x00; 96]),
        };

        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);

        let wire = tx.encode_wire();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        // Passes BLS verification and nonce check, dispatches to module query_params
        let receipt = executor
            .execute_native_tx(
                &wire,
                &block_ctx,
                &mut acp,
                &mut bulletin,
                &mut vera,
                &mut nonces,
                &mut test_journal(),
            )
            .unwrap();
        assert!(receipt.success(), "getParams query should succeed");
    }

    /// Build a signed native tx targeting ACP with a given nonce and keypair.
    fn signed_native_tx(sk: &ark_bls12_381::Fr, pk_bytes: &[u8], nonce: u64) -> Vec<u8> {
        let mut tx = NativeTx {
            chain_id: 9001,
            nonce,
            bls_pubkey: FixedBytes::from_slice(pk_bytes),
            target: ACP_ADDRESS,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        tx.encode_wire()
    }

    fn test_bls_keypair() -> (ark_bls12_381::Fr, Vec<u8>) {
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();
        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        (sk, pk_bytes)
    }

    #[test]
    fn native_decisions_bind_authenticated_sequence_and_revision() {
        use alloy_sol_types::SolCall;
        use vera_modules::acp::{
            abi::IAcp,
            decision::DecisionRequest,
            types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
        };
        let (sk, pk_bytes) = test_bls_keypair();
        let pubkey = bls::deserialize_pubkey(&pk_bytes).unwrap();
        let creator = bls::did_from_bls_pubkey(&pubkey).unwrap();
        let actor = creator.parse().unwrap();
        let mut acp = AcpModule::new();
        let policy = acp.create_policy(&actor, "name: decisions\nresources:\n  - name: file\n    permissions:\n      - name: read\n", PolicyMarshalingType::ShortYaml).unwrap().policy.id;
        let object = Object {
            resource: "file".into(),
            id: "report".into(),
        };
        acp.direct_policy_cmd(&actor, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap();
        let request = AccessRequest {
            actor: Actor(actor),
            operations: vec![Operation {
                object,
                permission: "read".into(),
            }],
        };
        let call = IAcp::checkAccessCall {
            policyId: FixedBytes::from_slice(&hex::decode(&policy).unwrap()),
            resources: vec!["file".into()],
            objectIds: vec!["report".into()],
            permissions: vec!["read".into()],
            actor: creator.clone(),
        };
        let executor = test_executor();
        let block = test_block_ctx();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();
        for sequence in 0..2 {
            let mut tx = NativeTx {
                chain_id: 9001,
                nonce: sequence,
                bls_pubkey: FixedBytes::from_slice(&pk_bytes),
                target: ACP_ADDRESS,
                calldata: call.abi_encode().into(),
                signature: FixedBytes::ZERO,
            };
            tx.signature = FixedBytes::from_slice(&bls::sign(&sk, &tx.signing_data()).unwrap());
            let result = executor
                .execute_native_tx(
                    &tx.encode_wire(),
                    &block,
                    &mut acp,
                    &mut bulletin,
                    &mut vera,
                    &mut nonces,
                    &mut test_journal(),
                )
                .unwrap();
            assert!(result.success());
            let expected = DecisionRequest {
                deployment_id: block.deployment_id,
                policy_id: policy.clone(),
                creator: creator.clone(),
                creator_sequence: sequence,
                request: request.clone(),
            };
            let decision = acp
                .query_access_decision(&expected.id().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(decision.creator_acc_sequence, sequence);
            assert_eq!(decision.creation_time, block.timestamp);
            assert_eq!(decision.issued_height, block.timestamp.block_height);
        }
    }

    #[test]
    fn native_tx_nonce_mismatch_rejected() {
        let (sk, pk_bytes) = test_bls_keypair();
        let wire = signed_native_tx(&sk, &pk_bytes, 5); // expected 0

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        match result {
            Err(ExecutionError::NonceMismatch { expected, got, .. }) => {
                assert_eq!(expected, 0);
                assert_eq!(got, 5);
            }
            other => panic!("expected NonceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn native_tx_sequential_nonces_accepted() {
        let (sk, pk_bytes) = test_bls_keypair();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        // nonce 0 passes nonce check; empty calldata fails ABI decode → failed receipt
        let wire_0 = signed_native_tx(&sk, &pk_bytes, 0);
        let result_0 = executor.execute_native_tx(
            &wire_0,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(result_0.is_ok(), "nonce 0 should pass: {result_0:?}");

        // nonce 1 also passes nonce check
        let wire_1 = signed_native_tx(&sk, &pk_bytes, 1);
        let result_1 = executor.execute_native_tx(
            &wire_1,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(result_1.is_ok(), "nonce 1 should pass: {result_1:?}");

        // Replay of nonce 0 should fail
        let wire_replay = signed_native_tx(&sk, &pk_bytes, 0);
        let result_replay = executor.execute_native_tx(
            &wire_replay,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(matches!(
            result_replay,
            Err(ExecutionError::NonceMismatch { .. })
        ));
    }

    #[test]
    fn native_tx_replay_rejected_after_success() {
        let (sk, pk_bytes) = test_bls_keypair();

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();

        // First: nonce 0 passes nonce check (empty calldata → failed receipt, but nonce consumed)
        let wire = signed_native_tx(&sk, &pk_bytes, 0);
        let result = executor.execute_native_tx(
            &wire,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        assert!(result.is_ok());

        // Replay: nonce 0 again should fail with NonceMismatch
        let wire_replay = signed_native_tx(&sk, &pk_bytes, 0);
        let result = executor.execute_native_tx(
            &wire_replay,
            &block_ctx,
            &mut acp,
            &mut bulletin,
            &mut vera,
            &mut nonces,
            &mut test_journal(),
        );
        match result {
            Err(ExecutionError::NonceMismatch { expected, got, .. }) => {
                assert_eq!(expected, 1);
                assert_eq!(got, 0);
            }
            other => panic!("expected NonceMismatch, got {other:?}"),
        }
    }
}
