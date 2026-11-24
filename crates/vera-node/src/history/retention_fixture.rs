//! A finalized chain with epoch artifacts, for pruning and import tests.

use std::{num::NonZeroU64, sync::Arc};

use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{Signer as _, ed25519};
use vera_domain::{DbTarget, Tx};

use super::*;
use crate::history::tests::block;

pub(super) const EPOCH: u64 = 8;
/// Seed of the single signer that certifies the chain.
pub(super) const SIGNER: u64 = 7;
/// A submission two early revisions carry.
pub(super) const PRUNED_TWICE: B256 = B256::repeat_byte(0xaa);
/// A submission an early and a late revision carry.
pub(super) const REPEATED: B256 = B256::repeat_byte(0xbb);

pub(super) fn epoch_length() -> NonZeroU64 {
    NonZeroU64::new(EPOCH).unwrap()
}

pub(super) fn submission(height: u64) -> B256 {
    match height {
        5 | 7 => PRUNED_TWICE,
        3 | 90 => REPEATED,
        height => B256::from(alloy_primitives::U256::from(height)),
    }
}

pub(super) struct Chain {
    pub history: FinalizedHistory,
    pub genesis: Block,
    pub blocks: Vec<Block>,
    pub directory: tempfile::TempDir,
}

/// The block at `height` after `parent`, with one submission, carrying the
/// epoch artifact when it ends an epoch.
pub(super) fn revision(height: u64, parent: BlockId) -> (Block, ExecutionReceipt) {
    static INFO: std::sync::LazyLock<crate::GenesisEpochInfo> = std::sync::LazyLock::new(|| {
        crate::trusted_setup(
            SIGNER,
            [ed25519::PrivateKey::from_seed(SIGNER).public_key()],
        )
        .unwrap()
        .0
    });
    let info = INFO.clone();
    let mut next = block(height, parent);
    next.context.round = Round::new(Epoch::new(height / EPOCH), View::new(height));
    next.txs.push(Tx::new(height.to_be_bytes().to_vec().into()));
    let receipt = ExecutionReceipt::new(submission(height), true, 3, 3, vec![]);
    next.native_targets = [DbTarget::default(); 4];
    next.receipt_commitment =
        vera_executor::receipt_commitment(100, std::slice::from_ref(&receipt));
    if (height + 1).is_multiple_of(EPOCH) {
        let mut info = info;
        info.epoch = Epoch::new((height + 1) / EPOCH);
        next.payload = Some(Payload::EpochInfo(info));
    }
    (next, receipt)
}

/// Revisions with a stored finalization in the block's epoch: a real one
/// by [`SIGNER`] when `certified`, placeholder bytes otherwise.
pub(super) fn chain_with(revisions: u64, certified: bool) -> Chain {
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
    history.db.skip_sync_for_test();
    let mut blocks = Vec::new();
    let mut parent = genesis.id();
    for height in 1..=revisions {
        let (next, receipt) = revision(height, parent);
        let finalization = if certified {
            let (light, _) = transfer::tests::certify(&next, SIGNER);
            hex::decode(light.finalization.trim_start_matches("0x")).unwrap()
        } else {
            height.to_be_bytes().to_vec()
        };
        let artifacts = FinalizationArtifacts {
            epoch: height / EPOCH,
            finalization,
            certificate: Vec::new(),
        };
        history
            .append_finalized(&next, &[receipt], 100, Some(&artifacts))
            .unwrap();
        parent = next.id();
        blocks.push(next);
    }
    Chain {
        history,
        genesis,
        blocks,
        directory,
    }
}

pub(super) fn chain(revisions: u64) -> Chain {
    chain_with(revisions, false)
}

impl Chain {
    pub(super) fn reopen(self) -> Self {
        let Self {
            history,
            genesis,
            blocks,
            directory,
        } = self;
        drop(history);
        let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
        Self {
            history,
            genesis,
            blocks,
            directory,
        }
    }

    pub(super) fn head(&self) -> &Block {
        self.blocks.last().unwrap()
    }

    pub(super) fn block(&self, height: u64) -> &Block {
        &self.blocks[height as usize - 1]
    }

    pub(super) async fn recover(&self, anchor: &Block) -> Result<LightBlockIndex> {
        recover(&self.history, &self.genesis, anchor).await
    }

    pub(super) fn holds(&self, prefix: u8, height: u64) -> bool {
        holds(&self.history, prefix, height)
    }

    pub(super) fn submission_height(&self, hash: B256) -> Option<u64> {
        self.history
            .db
            .get(query::hash_key(SUBMISSION_HASH, &hash.0))
            .unwrap()
            .map(|height| u64::from_be_bytes(height.try_into().unwrap()))
    }
}

pub(super) async fn recover(
    history: &FinalizedHistory,
    genesis: &Block,
    anchor: &Block,
) -> Result<LightBlockIndex> {
    let lookup: FinalizationLookup =
        Arc::new(|_| panic!("persisted certificates must not invoke network lookup"));
    let epochs = LightBlockIndex::new(epoch_length());
    history
        .recover(genesis, anchor, &BlockIndex::new(), &epochs, &lookup)
        .await?;
    Ok(epochs)
}

pub(super) fn holds(history: &FinalizedHistory, prefix: u8, height: u64) -> bool {
    history.db.get(key(prefix, height)).unwrap().is_some()
}

pub(super) fn pruned(error: &anyhow::Error) -> Option<HistoryPruned> {
    error.downcast_ref::<HistoryPruned>().copied()
}
