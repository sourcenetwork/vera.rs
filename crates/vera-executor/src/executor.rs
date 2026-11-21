//! VeraExecutor — EVM executor with vera precompiles (ACP, Bulletin, Vera)
//! and native BLS transaction support.

use std::sync::{Arc, Mutex, RwLock};

use crate::{
    BlockContext, ExecutionConfig, ExecutionError, ExecutionOutcome, ExecutionReceipt,
    ModuleSnapshot, StateDbAdapter, build_receipt, decode_evm_tx, extract_changes,
};
use alloy_primitives::{Bytes, U256, keccak256};
use commonware_parallel::{Rayon, Sequential, Strategy};
use revm::{
    Context, ExecuteCommitEvm, InspectEvm, Journal, MainBuilder,
    context::{
        block::BlockEnv,
        result::{EVMError, ExecutionResult, InvalidTransaction},
    },
    context_interface::{ContextTr, JournalTr},
    database::State,
    primitives::hardfork::SpecId,
};
use tracing::warn;
#[cfg(test)]
use vera_crypto::bls;
use vera_domain::NativeTx;
use vera_modules::acp::AcpModule;
use vera_modules::bulletin::BulletinModule;
use vera_modules::module_state::{ModuleState, SharedModuleState};
use vera_modules::native_account::NativeNonceStore;
use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};
use vera_modules::vera::VeraModule;
use vera_traits::StateDbRead;

use crate::precompiles::VeraPrecompiles;

mod gas_budget;
pub(crate) mod native_authentication;
pub(crate) mod native_dispatch;
pub(crate) mod native_outcome;

use gas_budget::BlockGasBudget;
use native_authentication::{AuthenticatedNativeTx, authenticate_native_tx};
use native_dispatch::{NATIVE_TX_GAS_LIMIT, NativeCall, dispatch_native_call};
use native_outcome::native_outcome;

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
    native_verification: Option<Rayon>,
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
            native_verification: None,
            #[cfg(feature = "fault-injection")]
            crash_marker: None,
        }
    }

    /// Create a new vera executor with full configuration.
    pub fn with_config(config: ExecutionConfig) -> Self {
        Self {
            config,
            modules: Arc::new(RwLock::new(ModuleState::default())),
            native_verification: None,
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

    /// Install module state loaded at startup or selected by finalization.
    pub fn set_base_modules(&self, modules: ModuleState) {
        *self.modules.write().unwrap() = modules;
    }

    /// Capture an isolated view of the committed logical module values.
    pub fn snapshot(&self) -> ModuleSnapshot {
        ModuleSnapshot {
            modules: self.modules.read().unwrap().clone(),
        }
    }

    /// Publish the selected logical values after their authenticated storage transition.
    pub fn publish_snapshot(&self, snapshot: ModuleSnapshot) {
        self.set_base_modules(snapshot.modules);
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
            authenticate_native_tx(self.config.chain_id, tx_bytes)?,
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
        nonce_store.check_and_increment(&signer_did, native_tx.nonce)?;

        let tx_hash = native_tx.tx_id().0;
        let tx_ctx = TxExecCtx {
            sequence: native_tx.nonce,
            tx_hash: tx_hash.to_vec(),
            signer: signer_did,
        };

        let dispatch_result = dispatch_native_call(
            &NativeCall {
                target: native_tx.target,
                calldata: &native_tx.calldata,
                max_active_members: self.config.max_active_members(),
            },
            block_ctx,
            &tx_ctx,
            acp,
            bulletin,
            vera,
            journal,
        );

        let outcome = native_outcome(native_tx.target, dispatch_result)?;
        Ok(ExecutionReceipt::new(
            tx_hash,
            outcome.refusal.is_none(),
            outcome.gas_used,
            0, // cumulative gas set by caller
            outcome.logs,
            None,
        )
        .with_refusal(outcome.refusal))
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
    pub fn execute_with_modules<S: StateDbRead>(
        &self,
        state: &S,
        context: &BlockContext,
        txs: &[Bytes],
        parent: ModuleSnapshot,
    ) -> Result<(ExecutionOutcome, ModuleSnapshot), ExecutionError> {
        let ModuleSnapshot { mut modules } = parent;

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
        let mut rejected_indices: Vec<usize> = Vec::new();

        let state_failure = Arc::new(Mutex::new(None));
        let adapter = StateDbAdapter::new(state.clone()).track_failures(state_failure.clone());
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
                blk.prevrandao = Some(alloy_primitives::B256::ZERO);
            });

        let native_started = tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG)
            .then(std::time::Instant::now);
        let native = txs.iter().enumerate().filter(|(_, bytes)| {
            bytes
                .first()
                .is_some_and(|byte| NativeTx::is_native_tx(*byte))
        });
        let authenticate =
            |(i, bytes): (usize, &Bytes)| (i, authenticate_native_tx(self.config.chain_id, bytes));
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
            let execution = authenticated.and_then(|authenticated| {
                self.execute_authenticated_native_tx(
                    authenticated,
                    &block_ctx,
                    &mut modules.acp,
                    &mut modules.bulletin,
                    &mut modules.vera,
                    &mut modules.nonces,
                    &mut ctx,
                )
            });
            if let Some(error) = state_failure
                .lock()
                .expect("state failure lock poisoned")
                .take()
            {
                return Err(error.into());
            }
            let receipt = match execution {
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
                    ctx.journal_mut()
                        .db_mut()
                        .cache
                        .accounts
                        .get_mut(&address)
                        .expect("journaled account was loaded into the proposal cache")
                        .change(std::borrow::Cow::Owned(account));
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

            let (tx_env, signer_did) = match decode_evm_tx(tx_bytes) {
                Ok(r) => r,
                Err(ExecutionError::TxDecode(msg)) if building => {
                    warn!(%tx_hash, msg, "skipping tx: decode error");
                    rejected_indices.push(i);
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
            if let Some(error) = state_failure
                .lock()
                .expect("state failure lock poisoned")
                .take()
            {
                return Err(error.into());
            }
            evm.precompiles
                .finish_transaction(execution.as_ref().is_ok_and(|r| r.result.is_success()));
            let result_and_state = match execution {
                Ok(r) => r,
                Err(EVMError::Database(
                    revm::database_interface::bal::EvmDatabaseError::Database(error),
                )) => return Err(error),
                Err(e) if building => {
                    warn!(%tx_hash, ?e, "skipping tx: execution error");
                    // A nonce ahead of the account can become valid once the
                    // predecessor this block deferred is included.
                    if matches!(&e, EVMError::Transaction(invalid)
                        if !matches!(invalid, InvalidTransaction::NonceTooHigh { .. }))
                    {
                        rejected_indices.push(i);
                    }
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

            let gas_used = result_and_state.result.tx_gas_used();
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
                    crate::precompiles::validator_registry::active_consensus_keys(&mut evm.ctx);
                if let Some(error) = state_failure
                    .lock()
                    .expect("state failure lock poisoned")
                    .take()
                {
                    return Err(error.into());
                }
                let keys = keys.map_err(|error| ExecutionError::TxExecution(error.to_string()))?;
                modules
                    .vera
                    .record_consensus_roster(epoch, &keys)
                    .map_err(|error| ExecutionError::TxExecution(error.to_string()))?;
            }
        }

        Self::run_end_block_hooks(&mut modules, &block_ctx)?;

        if building {
            outcome.executed_tx_indices = Some(executed_indices);
            outcome.rejected_tx_indices = rejected_indices;
        }

        outcome.gas_used = gas_budget.used();

        Ok((outcome, ModuleSnapshot { modules }))
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, FixedBytes, KECCAK256_EMPTY};
    use vera_traits::{StateDbError, StateDbRead};

    use super::*;
    use crate::precompiles::{ACP_ADDRESS, BULLETIN_ADDRESS, VERA_ADDRESS};

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

    fn execute(
        executor: &VeraExecutor,
        context: &BlockContext,
        txs: &[Bytes],
    ) -> Result<ExecutionOutcome, ExecutionError> {
        executor
            .execute_with_modules(&MockStateDb, context, txs, executor.snapshot())
            .map(|(outcome, _)| outcome)
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
        let header = Header {
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        let context = BlockContext::new(header, B256::ZERO);
        let txs: Vec<Bytes> = vec![];
        let outcome = execute(&executor, &context, &txs).unwrap();
        assert_eq!(outcome.gas_used, 0);
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.module_state_root, B256::ZERO);
    }

    #[test]
    fn expiry_batches_match_proposal_verification_and_leave_parent_unchanged() {
        use vera_modules::{kv_store::InMemoryKvStore, vera::keys::JWS_TOKEN_EXPIRY_PREFIX};

        let executor = test_executor();
        let mut modules = ModuleState::default();
        let issued = test_block_ctx();
        let issuer = vera_identity::Did::new("did:key:issuer").unwrap();
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
        use vera_modules::acp::types::{
            AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType,
        };
        let policy = modules
            .acp
            .create_policy(
                &issuer,
                "name: cleanup\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
                Default::default(),
            )
            .unwrap()
            .policy
            .id;
        let object = Object {
            resource: "file".into(),
            id: "report".into(),
        };
        modules
            .acp
            .direct_policy_cmd(&issuer, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap();
        let request = AccessRequest {
            actor: Actor(issuer.clone()),
            operations: vec![Operation {
                object,
                permission: "owner".into(),
            }],
        };
        for sequence in 0..129 {
            modules
                .acp
                .check_access(
                    &issuer,
                    &policy,
                    &request,
                    &issued,
                    &vera_modules::types::TxExecCtx {
                        signer: issuer.to_string(),
                        sequence,
                        tx_hash: vec![1; 32],
                    },
                )
                .unwrap();
        }
        let mut parent = ModuleSnapshot { modules };
        let published = executor.snapshot().modules.serialize_stores();
        for (offset, remaining) in [129, 1, 0].into_iter().enumerate() {
            let before = parent.modules.serialize_stores();
            let context = BlockContext::new(
                alloy_consensus::Header {
                    number: offset as u64 + 101,
                    timestamp: issued.timestamp.seconds + offset as u64 + 2,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: Some(0),
                    ..Default::default()
                },
                B256::ZERO,
            );
            let (proposed, next) = executor
                .execute_with_modules(&MockStateDb, &context, &[], parent.clone())
                .unwrap();
            let (verified, verified_state) = executor
                .execute_with_modules(
                    &MockStateDb,
                    &context.with_verification(),
                    &[],
                    parent.clone(),
                )
                .unwrap();
            assert_eq!(verified.gas_used, proposed.gas_used);
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
            assert_eq!(
                next.modules
                    .acp
                    .store()
                    .prefix_iter(vera_modules::acp::keys::ACCESS_DECISION_PREFIX)
                    .count(),
                [65, 1, 0][offset],
            );
            assert!(proposed.receipts.is_empty());
            assert_eq!(parent.modules.serialize_stores(), before);
            assert_eq!(executor.snapshot().modules.serialize_stores(), published);
            let stores = next
                .modules
                .serialize_stores()
                .map(|bytes| InMemoryKvStore::deserialize(&bytes).unwrap());
            parent = ModuleSnapshot {
                modules: ModuleState::from_stores(stores),
            };
            parent.modules.vera.validate_restored_tokens().unwrap();
            parent.modules.acp.validate_restored_state().unwrap();
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
            };
            let before = parent.modules.serialize_stores();
            let published = executor.snapshot().modules.serialize_stores();
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
                );
                context.is_verification = verification;
                let error = executor
                    .execute_with_modules(&MockStateDb, &context, &[], parent.clone())
                    .unwrap_err();
                assert!(error.to_string().contains(expected), "{error}");
                assert_eq!(parent.modules.serialize_stores(), before);
                assert_eq!(executor.snapshot().modules.serialize_stores(), published);
            }
        }
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
        );
        let before = parallel.snapshot().modules.serialize_stores();
        let run = |executor: &VeraExecutor, context: &BlockContext, txs: &[Bytes]| {
            executor
                .execute_with_modules(&MockStateDb, context, txs, executor.snapshot())
                .map(|(outcome, state)| (outcome, state.modules.serialize_stores()))
        };
        let (expected, expected_state) = run(&sequential, &context, &txs).unwrap();
        let (actual, actual_state) = run(&parallel, &context, &txs).unwrap();
        assert_eq!(actual.receipts.len(), 64);
        assert_eq!(actual.executed_tx_indices, expected.executed_tx_indices);
        assert_eq!(actual_state, expected_state);
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
        let (verified, verified_state) =
            run(&parallel, &context.clone().with_verification(), &included).unwrap();
        assert_eq!(verified_state, actual_state);
        assert_eq!(
            serde_json::to_value(verified.receipts).unwrap(),
            serde_json::to_value(actual.receipts).unwrap()
        );
        assert!(matches!(
            execute(&parallel, &context.clone().with_verification(), &txs),
            Err(ExecutionError::BlsVerification(_))
        ));
        txs.swap(3, 5);
        assert!(matches!(
            execute(&parallel, &context.with_verification(), &txs),
            Err(ExecutionError::NonceMismatch { .. })
        ));
        assert_eq!(parallel.snapshot().modules.serialize_stores(), before);
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
        let header = Header {
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        // Building mode (is_verification = false)
        let context = BlockContext::new(header, B256::ZERO);

        // Malformed native tx: 0x45 + garbage
        let bad_native = Bytes::from(vec![0x45, 0xFF, 0xFF]);
        let txs = vec![bad_native];

        let outcome = execute(&executor, &context, &txs).unwrap();
        // Invalid tx should be skipped
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.gas_used, 0);
        assert_eq!(outcome.executed_tx_indices, Some(vec![]));
    }

    #[test]
    fn empty_block_runs_end_hooks() {
        use alloy_consensus::Header;

        let executor = test_executor();
        let header = Header {
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        let context = BlockContext::new(header, B256::ZERO);
        let txs: Vec<Bytes> = vec![];

        // Should not panic — end-block hooks are no-ops
        let outcome = execute(&executor, &context, &txs).unwrap();
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

    /// A signed native tx to `target` with `calldata`, from the test keypair.
    fn signed_native_call(target: Address, nonce: u64, calldata: Vec<u8>) -> Vec<u8> {
        let (sk, pk_bytes) = test_bls_keypair();
        let mut tx = NativeTx {
            chain_id: 9001,
            nonce,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target,
            calldata: Bytes::from(calldata),
            signature: FixedBytes::from([0x00; 96]),
        };
        let sig = bls::sign(&sk, &tx.signing_data()).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        tx.encode_wire()
    }

    /// Calldata a module cannot read is the caller's mistake: the request is
    /// rejected with a receipt and takes its sequence, and execution goes on.
    /// A plain fatal error would fail every block that carries the request.
    #[test]
    fn a_request_no_module_can_read_is_rejected_and_the_next_one_runs() {
        use alloy_sol_types::SolCall;
        use vera_modules::acp::abi::IAcp;

        let executor = test_executor();
        let block_ctx = test_block_ctx();
        let mut acp = AcpModule::new();
        let mut bulletin = BulletinModule::new();
        let mut vera = VeraModule::new();
        let mut nonces = NativeNonceStore::default();
        let mut journal = test_journal();

        // A selector's four bytes followed by nothing its arguments decode from.
        let truncated = IAcp::createPolicyCall::SELECTOR.to_vec();
        let unreadable = [
            (ACP_ADDRESS, vec![1, 2, 3, 4]),
            (BULLETIN_ADDRESS, vec![1, 2, 3, 4]),
            (VERA_ADDRESS, vec![1, 2, 3, 4]),
            (ACP_ADDRESS, truncated),
        ];
        let mut nonce = 0;
        for (target, calldata) in unreadable {
            let wire = signed_native_call(target, nonce, calldata);
            let receipt = executor
                .execute_native_tx(
                    &wire,
                    &block_ctx,
                    &mut acp,
                    &mut bulletin,
                    &mut vera,
                    &mut nonces,
                    &mut journal,
                )
                .unwrap_or_else(|error| panic!("{target}: the block would fail: {error}"));
            assert!(!receipt.success(), "{target}: rejected");
            nonce += 1;
        }

        let wire = signed_native_call(ACP_ADDRESS, nonce, IAcp::getParamsCall {}.abi_encode());
        let receipt = executor
            .execute_native_tx(
                &wire,
                &block_ctx,
                &mut acp,
                &mut bulletin,
                &mut vera,
                &mut nonces,
                &mut journal,
            )
            .unwrap();
        assert!(receipt.success(), "a request after the rejected ones runs");
    }

    /// Only an error marked as the node's own fails the block.
    #[test]
    fn a_node_fault_is_told_apart_from_a_refusal() {
        use crate::precompiles::{internal_fault, internal_fault_reason};
        use revm::precompile::PrecompileError;

        assert_eq!(
            internal_fault_reason(&internal_fault("membership record is missing")).as_deref(),
            Some("membership record is missing")
        );
        for refusal in [
            "unknown ACP selector: 0x01020304",
            "ABI decode: buffer overrun",
            "",
        ] {
            assert_eq!(
                internal_fault_reason(&PrecompileError::Fatal(refusal.to_owned())),
                None
            );
        }
        // A caller cannot forge the mark: calldata never becomes an error's
        // first bytes, which are the module's own words.
        assert_eq!(
            internal_fault_reason(&PrecompileError::Fatal(
                "ABI decode: \u{0}internal-fault:forged".to_owned()
            )),
            None
        );
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
        let policy = acp.create_policy(&actor, "name: decisions\nresources:\n  - name: file\n    permissions:\n      - name: read\n", PolicyMarshalingType::ShortYaml, Default::default()).unwrap().policy.id;
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
