//! Pruning finalized history below a floor, and reads at and below it.

use std::{num::NonZeroU64, sync::Arc};

use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{Signer as _, ed25519};
use vera_domain::{DbTarget, Tx};
use vera_indexer::IndexQuery;

use super::*;
use crate::history::tests::block;

const EPOCH: u64 = 8;
/// A submission two pruned revisions carry.
const PRUNED_TWICE: B256 = B256::repeat_byte(0xaa);
/// A submission a pruned and a retained revision carry.
const REPEATED: B256 = B256::repeat_byte(0xbb);

fn epoch_length() -> NonZeroU64 {
    NonZeroU64::new(EPOCH).unwrap()
}

fn submission(height: u64) -> B256 {
    match height {
        5 | 7 => PRUNED_TWICE,
        3 | 90 => REPEATED,
        height => B256::from(alloy_primitives::U256::from(height)),
    }
}

struct Chain {
    history: FinalizedHistory,
    genesis: Block,
    blocks: Vec<Block>,
    directory: tempfile::TempDir,
}

/// Revisions with one submission each, the epoch artifact on the last block
/// of every epoch, and a stored finalization in the block's epoch.
fn chain(revisions: u64) -> Chain {
    let directory = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history = FinalizedHistory::open(directory.path(), &genesis).unwrap();
    history.db.skip_sync_for_test();
    let (info, _) =
        crate::trusted_setup(7, [ed25519::PrivateKey::from_seed(7).public_key()]).unwrap();
    let mut blocks = Vec::new();
    let mut parent = genesis.id();
    for height in 1..=revisions {
        let mut next = block(height, parent);
        next.context.round = Round::new(Epoch::new(height / EPOCH), View::new(height));
        next.txs.push(Tx::new(height.to_be_bytes().to_vec().into()));
        let receipt = ExecutionReceipt::new(submission(height), true, 3, 3, vec![], None);
        next.native_targets = Some([DbTarget::default(); 4]);
        next.receipt_commitment = Some(vera_executor::receipt_commitment(
            100,
            std::slice::from_ref(&receipt),
        ));
        if (height + 1).is_multiple_of(EPOCH) {
            let mut info = info.clone();
            info.epoch = Epoch::new((height + 1) / EPOCH);
            next.payload = Some(Payload::EpochInfo(info));
        }
        let artifacts = FinalizationArtifacts {
            epoch: height / EPOCH,
            finalization: height.to_be_bytes().to_vec(),
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

impl Chain {
    fn reopen(self) -> Self {
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

    fn head(&self) -> &Block {
        self.blocks.last().unwrap()
    }

    async fn recover(&self, anchor: &Block) -> Result<LightBlockIndex> {
        let lookup: FinalizationLookup =
            Arc::new(|_| panic!("persisted certificates must not invoke network lookup"));
        let epochs = LightBlockIndex::new(epoch_length());
        self.history
            .recover(&self.genesis, anchor, &BlockIndex::new(), &epochs, &lookup)
            .await?;
        Ok(epochs)
    }

    fn holds(&self, prefix: u8, height: u64) -> bool {
        self.history.db.get(key(prefix, height)).unwrap().is_some()
    }

    fn submission_height(&self, hash: B256) -> Option<u64> {
        self.history
            .db
            .get(query::hash_key(SUBMISSION_HASH, &hash.0))
            .unwrap()
            .map(|height| u64::from_be_bytes(height.try_into().unwrap()))
    }
}

fn pruned(error: &anyhow::Error) -> Option<HistoryPruned> {
    error.downcast_ref::<HistoryPruned>().copied()
}

#[tokio::test]
async fn a_pruned_store_keeps_epoch_boundaries_and_recovers_from_its_floor() {
    let chain = chain(100);
    assert_eq!(chain.history.floor_height().unwrap(), 1);
    assert_eq!(chain.history.prune_below(50, epoch_length()).unwrap(), 50);
    assert_eq!(chain.history.floor_height().unwrap(), 50);
    for height in 1..50 {
        let boundary = height % EPOCH == 0 || (height + 1) % EPOCH == 0;
        assert_eq!(chain.holds(RECORD, height), boundary, "record {height}");
        assert!(!chain.holds(CERTIFICATE, height), "certificate {height}");
    }
    for height in 50..=100 {
        assert!(chain.holds(RECORD, height) && chain.holds(CERTIFICATE, height));
    }
    // A target at or below the floor changes nothing, and the head always stays.
    assert_eq!(chain.history.prune_below(20, epoch_length()).unwrap(), 50);

    let chain = chain.reopen();
    let anchor = chain.blocks[39].clone();
    let error = chain.recover(&anchor).await.unwrap_err();
    assert_eq!(
        pruned(&error),
        Some(HistoryPruned {
            height: 40,
            floor: 50
        })
    );
    assert_eq!(
        chain.history.head_height(),
        100,
        "a refused recovery cuts nothing"
    );

    let head = chain.head().clone();
    let validated = chain.recover(&head).await.unwrap();
    chain.history.db.delete(VALIDATED).unwrap();
    let chain = chain.reopen();
    let full = chain.recover(&head).await.unwrap();
    assert_eq!(validated.stats(), full.stats());
    for epoch in 0..=100 / EPOCH + 1 {
        assert_eq!(
            validated.get_epoch_material(epoch),
            full.get_epoch_material(epoch),
            "epoch {epoch}"
        );
    }

    // The block at the floor is the one the floor names.
    let other = block(50, BlockId(B256::repeat_byte(3)));
    let record = Record {
        block: other.encode().to_vec(),
        gas_limit: 100,
        receipts: Vec::new(),
    };
    chain
        .history
        .db
        .put(key(RECORD, 50), borsh::to_vec(&record).unwrap())
        .unwrap();
    chain.history.db.delete(VALIDATED).unwrap();
    let chain = chain.reopen();
    let error = chain.recover(&head).await.unwrap_err();
    assert!(error.to_string().contains("its floor"), "{error}");
}

#[test]
fn hash_mappings_are_removed_only_for_pruned_revisions() {
    let chain = chain(100);
    assert_eq!(chain.submission_height(PRUNED_TWICE), Some(7));
    assert_eq!(chain.submission_height(REPEATED), Some(90));
    chain.history.prune_below(40, epoch_length()).unwrap();
    assert_eq!(chain.submission_height(PRUNED_TWICE), None);
    assert_eq!(chain.submission_height(REPEATED), Some(90));
    assert_eq!(chain.submission_height(submission(10)), None);
    assert_eq!(chain.submission_height(submission(40)), Some(40));
    for (height, block) in (1..).zip(&chain.blocks) {
        let mapped = chain.history.execution_by_hash(block.id().0).unwrap();
        assert_eq!(mapped.is_some(), height >= 40, "revision {height}");
    }
    let repeated = chain.history.execution_by_submission(REPEATED).unwrap();
    assert_eq!(repeated.unwrap().block.height, 90);
}

#[test]
fn reads_below_the_floor_are_refused_and_retained_revisions_still_prove() {
    let chain = chain(100);
    chain.history.prune_below(60, epoch_length()).unwrap();
    let floor = |height| HistoryPruned { height, floor: 60 };
    // No epoch material is cached: the proofs read it from retained boundaries,
    // epoch 7's from block 55, below the floor.
    let epochs = LightBlockIndex::new(epoch_length());
    for height in [60, 64, 99] {
        let light = chain.history.light_block(height, &epochs).unwrap();
        assert_eq!(light.height, height);
        assert_eq!(light.epoch, height / EPOCH);
    }
    for height in [1, 55, 56, 59] {
        let error = chain.history.light_block(height, &epochs).unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "proof {height}");
        let error = chain
            .history
            .record_chunk(height, 0, HISTORY_CHUNK_BYTES)
            .unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "chunk {height}");
        let error = chain
            .history
            .execution_bounded(IndexQuery::Revision(height), &mut usize::MAX.clone())
            .unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "revision {height}");
        let error = chain.history.stored_block(height).unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "block {height}");
    }
    assert!(chain.history.stored_block(60).unwrap().is_some());
    assert!(
        chain
            .history
            .certified_light_block(30, &epochs)
            .is_err_and(|error| pruned(&error).is_some()),
        "a pruned revision is not pending finality"
    );

    // Rosters of every epoch stay readable from the boundaries.
    for epoch in 2..=100 / EPOCH {
        let roster = chain
            .history
            .consensus_roster(Epoch::new(epoch), epoch_length())
            .unwrap();
        assert!(roster.is_some(), "epoch {epoch}");
    }

    // A cut needs the block it goes back to.
    let cut = chain.blocks[49].id().0;
    let error = chain.history.standing(50, &cut, 1).unwrap_err();
    assert_eq!(pruned(&error), Some(floor(50)));
    let error = chain.history.rewind_to(50).unwrap_err();
    assert_eq!(pruned(&error), Some(floor(50)));
    let error = chain.history.rewind_to(0).unwrap_err();
    assert_eq!(pruned(&error), Some(floor(0)));
    assert_eq!(chain.history.head_height(), 100);
    chain.history.rewind_to(60).unwrap();
    assert_eq!(chain.history.head_height(), 60);
}

#[test]
fn a_pruned_submission_is_not_found_and_never_pending() {
    let chain = chain(100);
    chain.history.prune_below(60, epoch_length()).unwrap();
    let epochs = LightBlockIndex::new(epoch_length());
    // Its mapping went with its record: the lookup finds nothing.
    assert!(
        chain
            .history
            .receipt_proof(submission(30), &epochs)
            .unwrap()
            .is_none()
    );
    assert!(
        chain
            .history
            .receipt_proof(submission(70), &epochs)
            .unwrap()
            .is_some()
    );
    // A mapping that still names a pruned revision is refused, not pending.
    let mut batch = WriteBatch::default();
    query::index_submission(&mut batch, &submission(30).0, 30);
    write(&chain.history.db, batch).unwrap();
    let error = chain
        .history
        .receipt_proof(submission(30), &epochs)
        .unwrap_err();
    assert_eq!(
        pruned(&error),
        Some(HistoryPruned {
            height: 30,
            floor: 60
        })
    );
}

#[tokio::test]
async fn a_crash_between_prune_batches_leaves_a_floor_matching_the_records() {
    let chain = chain(700);
    let mut batches = 0;
    let error = chain
        .history
        .prune_below_with(650, epoch_length(), |db, batch| {
            batches += 1;
            ensure!(batches == 1, "injected crash");
            write(db, batch)
        })
        .unwrap_err();
    assert!(error.to_string().contains("injected crash"));
    let chain = chain.reopen();
    let floor = chain.history.floor_height().unwrap();
    assert_eq!(floor, 257);
    assert!(!chain.holds(RECORD, floor - 3));
    assert!(chain.holds(RECORD, floor) && chain.holds(CERTIFICATE, floor));
    assert!(!chain.holds(CERTIFICATE, floor - 1));
    chain.history.db.delete(VALIDATED).unwrap();
    let chain = chain.reopen();
    let head = chain.head().clone();
    chain.recover(&head).await.unwrap();
    assert_eq!(chain.history.prune_below(650, epoch_length()).unwrap(), 650);
    chain.recover(&head).await.unwrap();
}

#[test]
fn a_maintenance_pass_keeps_the_retained_window_and_bounds_its_work() {
    let chain = chain(1_400);
    let retention = HistoryRetention {
        retained: 100,
        interval: NonZeroU64::new(4).unwrap(),
        epoch_length: epoch_length(),
    };
    assert!(retention.due(1_400) && !retention.due(1_401));
    // One pass removes at most four batches.
    assert_eq!(chain.history.maintain(&retention).unwrap(), 1_025);
    assert_eq!(chain.history.maintain(&retention).unwrap(), 1_300);
    assert_eq!(chain.history.maintain(&retention).unwrap(), 1_300);
}

#[test]
fn a_retention_below_the_windows_read_below_the_head_is_refused() {
    let minimum = minimum_history_retention(epoch_length());
    assert_eq!(minimum, 1_024 + 1_024 + 2 * EPOCH);
    assert_eq!(
        check_history_retention(minimum - 1, epoch_length()),
        Err(RetentionTooShort {
            retained: minimum - 1,
            minimum
        })
    );
    assert_eq!(check_history_retention(minimum, epoch_length()), Ok(()));
}
