use commonware_glue::stateful::db::DatabaseSet;
use vera_backend::Ctx;
use vera_domain::{Block, DbTarget, DbTargets, StateRoot, Tx};
use vera_executor::{BlockContext, ExecutionOutcome, ExecutionReceipt, VeraExecutor};

use crate::{AppError, ordered_state::OrderedState};

/// Executed commitments and receipts carried into the application callback.
pub struct StateExecution<D: ApplicationState> {
    pub(crate) batches: D::Merkleized,
    pub(crate) state_root: StateRoot,
    pub(crate) db_targets: DbTargets,
    pub(crate) native_targets: Option<[DbTarget; 4]>,
    pub(crate) outcome: ExecutionOutcome,
}

impl<D: ApplicationState> std::fmt::Debug for StateExecution<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateExecution")
            .field("state_root", &self.state_root)
            .field("db_targets", &self.db_targets)
            .field("native_targets", &self.native_targets)
            .finish_non_exhaustive()
    }
}

/// Storage-specific execution used by the shared proposal and verification path.
pub trait ApplicationState: DatabaseSet<Ctx> + Clone + Send + Sync + 'static {
    /// Whether the block carries commitments for this storage layout.
    fn accepts(block: &Block) -> bool;
    /// Targets from a block whose storage layout has already been checked.
    fn targets(block: &Block) -> Self::SyncTargets;
    /// Attach execution receipts to their sealed proposal, outside storage commitments.
    fn with_receipts(
        batches: Self::Merkleized,
        receipts: Vec<ExecutionReceipt>,
    ) -> Self::Merkleized;
    /// Receipts produced by this proposal's execution or verified replay.
    fn receipts(batches: &Self::Merkleized) -> &[ExecutionReceipt];
    /// Execute and seal one proposal against its parent's isolated batches.
    fn execute(
        executor: &VeraExecutor,
        batches: Self::Unmerkleized,
        context: &BlockContext,
        txs: &[Tx],
    ) -> impl Future<Output = Result<StateExecution<Self>, AppError>> + Send;
}

impl ApplicationState for OrderedState {
    fn with_receipts(
        mut batches: Self::Merkleized,
        receipts: Vec<ExecutionReceipt>,
    ) -> Self::Merkleized {
        batches.receipts = Some(receipts.into());
        batches
    }

    fn receipts(batches: &Self::Merkleized) -> &[ExecutionReceipt] {
        batches
            .receipts
            .as_deref()
            .expect("sealed application execution must carry its receipts")
    }

    fn accepts(block: &Block) -> bool {
        block.native_targets.is_some() && block.receipt_commitment.is_some()
    }
    fn targets(block: &Block) -> Self::SyncTargets {
        let execution = crate::sync_targets(&block.db_targets);
        let native = block
            .native_targets
            .as_ref()
            .expect("ordered block commitments")
            .map(|target| crate::targets::sync_from_target(&target));
        (
            execution.0,
            execution.1,
            execution.2,
            native[0].clone(),
            native[1].clone(),
            native[2].clone(),
            native[3].clone(),
            Some(block.module_state_root.0.into()),
        )
    }
    async fn execute(
        executor: &VeraExecutor,
        batches: Self::Unmerkleized,
        context: &BlockContext,
        txs: &[Tx],
    ) -> Result<StateExecution<Self>, AppError> {
        let (batches, outcome) = Self::execute_on(executor, batches, context, txs).await?;
        let targets = batches.sync_targets();
        let db_targets = crate::db_targets_from_sync(&(targets.0, targets.1, targets.2));
        let native_targets = [targets.3, targets.4, targets.5, targets.6]
            .each_ref()
            .map(crate::targets::target_from_sync);
        Ok(StateExecution {
            batches,
            state_root: StateRoot(vera_qmdb::StateRoot::compute(
                db_targets.accounts.root.0.into(),
                db_targets.storage.root.0.into(),
                db_targets.code.root.0.into(),
            )),
            db_targets,
            native_targets: Some(native_targets),
            outcome,
        })
    }
}
