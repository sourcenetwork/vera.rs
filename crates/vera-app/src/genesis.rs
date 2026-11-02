//! Seed a fresh state set from genesis and build the genesis block.

use std::collections::BTreeMap;

use alloy_primitives::{B256, KECCAK256_EMPTY, U256, keccak256};
use commonware_glue::stateful::db::DatabaseSet as _;
use vera_backend::{BatchState, VeraStateSet, combined_root};
use vera_domain::{Block, BlockId, DbTargets, StateRoot};
use vera_genesis::GenesisState;
use vera_qmdb::{AccountUpdate, ChangeSet};

use crate::{AppError, db_targets_from_merkleized};

const fn fresh_account() -> AccountUpdate {
    AccountUpdate {
        created: true,
        selfdestructed: false,
        nonce: 0,
        balance: U256::ZERO,
        code_hash: KECCAK256_EMPTY,
        code: None,
        storage: BTreeMap::new(),
    }
}

/// Apply genesis balances, storage, and code to an empty set and finalize.
///
/// Returns the combined root and per-partition targets the genesis block records.
pub async fn apply_genesis(
    set: &VeraStateSet,
    genesis: &GenesisState,
) -> Result<(StateRoot, DbTargets), AppError> {
    let mut changes = ChangeSet::new();
    for (address, balance) in &genesis.genesis_alloc {
        let update = changes
            .accounts
            .entry(*address)
            .or_insert_with(fresh_account);
        update.balance = *balance;
    }
    for (address, code) in &genesis.genesis_code {
        let update = changes
            .accounts
            .entry(*address)
            .or_insert_with(fresh_account);
        update.code_hash = keccak256(code);
        update.code = Some(code.clone());
    }
    for (address, slots) in &genesis.genesis_storage {
        let update = changes
            .accounts
            .entry(*address)
            .or_insert_with(fresh_account);
        for (slot, value) in slots {
            update.storage.insert(*slot, *value);
        }
    }

    let batches = set.new_batches().await;
    let batches = BatchState::apply_changes(batches, &changes).await?;
    let merkleized = BatchState::merkleize(batches).await?;
    let root = StateRoot(combined_root(&merkleized));
    let targets = db_targets_from_merkleized(&merkleized);
    set.apply(merkleized).await;
    if !set.finalize().await.durable().await {
        return Err(AppError::Execution("genesis did not become durable".into()));
    }
    Ok((root, targets))
}

/// The genesis block for a chain whose state set holds the genesis state.
pub fn genesis_block(
    state_root: StateRoot,
    db_targets: DbTargets,
    module_state_root: B256,
) -> Block {
    Block {
        context: Block::genesis_context(),
        parent: BlockId(B256::ZERO),
        height: 0,
        timestamp: 0,
        prevrandao: B256::ZERO,
        randomness: None,
        state_root,
        module_state_root,
        txs: Vec::new(),
        payload: None,
        native_targets: None,
        receipt_commitment: None,
        db_targets,
    }
}
