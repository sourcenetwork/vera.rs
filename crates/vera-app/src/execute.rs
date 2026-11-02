//! Execute a block's transactions against forked state batches.

use alloy_primitives::Bytes;
use vera_backend::{BatchState, VeraMerkleized, VeraUnmerkleized, combined_root};
use vera_domain::{DbTargets, StateRoot, Tx};
use vera_executor::{BlockContext, ExecutionOutcome, ModuleSnapshot, VeraExecutor};

use crate::{AppError, db_targets_from_merkleized};

/// Result of executing transactions on top of a parent's pending state.
pub struct Executed {
    /// Merkleized batches holding the post-execution state.
    pub merkleized: VeraMerkleized,
    /// Combined EVM state root.
    pub state_root: StateRoot,
    /// Per-partition targets for the block.
    pub db_targets: DbTargets,
    /// Receipts, module root, and executed transaction indices.
    pub outcome: ExecutionOutcome,
    /// Module state produced from the supplied parent snapshot.
    pub modules: ModuleSnapshot,
}

impl std::fmt::Debug for Executed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executed")
            .field("state_root", &self.state_root)
            .field("db_targets", &self.db_targets)
            .field("gas_used", &self.outcome.gas_used)
            .finish_non_exhaustive()
    }
}

/// Run `txs` through the executor on `batches`, write the resulting changes, and merkleize.
pub async fn execute_block(
    executor: &VeraExecutor,
    batches: VeraUnmerkleized,
    context: &BlockContext,
    txs: &[Tx],
    modules: ModuleSnapshot,
) -> Result<Executed, AppError> {
    let state = BatchState::new(batches);
    let tx_bytes: Vec<Bytes> = txs.iter().map(|tx| tx.bytes.clone()).collect();
    let (outcome, modules) = executor.execute_with_modules(&state, context, &tx_bytes, modules)?;
    let batches = state.into_batches().await?;
    let batches = BatchState::apply_changes(batches, &outcome.changes).await?;
    let merkleized = BatchState::merkleize(batches).await?;
    Ok(Executed {
        state_root: StateRoot(combined_root(&merkleized)),
        db_targets: db_targets_from_merkleized(&merkleized),
        merkleized,
        outcome,
        modules,
    })
}
