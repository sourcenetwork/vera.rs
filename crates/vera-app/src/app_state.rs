use commonware_glue::stateful::db::DatabaseSet;
use vera_backend::Ctx;
use vera_domain::{Block, DbTarget, Tx};
use vera_executor::{BlockContext, ExecutionOutcome, ExecutionReceipt, VeraExecutor};

use crate::{AppError, ordered_state::OrderedState};

/// Executed commitments and receipts carried into the application callback.
pub struct StateExecution<D: ApplicationState> {
    pub(crate) batches: D::Merkleized,
    pub(crate) native_targets: [DbTarget; 4],
    pub(crate) outcome: ExecutionOutcome,
}

impl<D: ApplicationState> std::fmt::Debug for StateExecution<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateExecution")
            .field("native_targets", &self.native_targets)
            .finish_non_exhaustive()
    }
}

/// Storage-specific execution used by the shared proposal and verification path.
pub trait ApplicationState: DatabaseSet<Ctx> + Clone + Send + Sync + 'static {
    /// Whether the block's targets name ranges this storage can reach.
    fn accepts(block: &Block) -> bool;
    /// Targets a block commits to. Consensus asks for these before the block is
    /// verified, so a block [`Self::accepts`] rejects yields a placeholder.
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
        crate::targets::block_targets_well_formed(block)
    }
    fn targets(block: &Block) -> Self::SyncTargets {
        if !crate::targets::block_targets_well_formed(block) {
            return Self::initial_sync_targets();
        }
        let native = block
            .native_targets
            .map(|target| crate::targets::sync_from_target(&target));
        (
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
        let native_targets = [targets.0, targets.1, targets.2, targets.3]
            .each_ref()
            .map(crate::targets::target_from_sync);
        Ok(StateExecution {
            batches,
            native_targets,
            outcome,
        })
    }
}
