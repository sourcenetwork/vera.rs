//! Pruning finalized history below an epoch-aligned floor, and reads at and below it.

use std::num::NonZeroU64;

use commonware_consensus::types::Epoch;
use vera_indexer::IndexQuery;

use super::*;
use crate::history::retention::fixture::{
    EPOCH, PRUNED_TWICE, REPEATED, chain, epoch_length, pruned, submission,
};

#[tokio::test]
async fn a_pruned_store_holds_one_run_from_the_floors_parent_and_recovers_from_it() {
    let chain = chain(100);
    assert_eq!(chain.history.floor_height().unwrap(), 1);
    // The target rounds down to the first block of its epoch.
    assert_eq!(chain.history.prune_below(50, epoch_length()).unwrap(), 48);
    assert_eq!(chain.history.floor_height().unwrap(), 48);
    for height in 1..=100 {
        assert_eq!(chain.holds(RECORD, height), height >= 47, "record {height}");
        assert_eq!(
            chain.holds(CERTIFICATE, height),
            height >= 48,
            "certificate {height}"
        );
    }
    // A target at or below the floor changes nothing.
    assert_eq!(chain.history.prune_below(20, epoch_length()).unwrap(), 48);
    // The head's epoch stays.
    assert_eq!(
        chain.history.prune_below(1_000, epoch_length()).unwrap(),
        96
    );
    assert!(chain.holds(RECORD, 95) && !chain.holds(RECORD, 94));

    let chain = chain.reopen();
    let error = chain.recover(chain.block(90)).await.unwrap_err();
    assert_eq!(
        pruned(&error),
        Some(HistoryPruned {
            height: 90,
            floor: 96
        })
    );
    assert_eq!(
        chain.history.head_height(),
        100,
        "a refused recovery cuts nothing"
    );

    let head = chain.head().clone();
    let validated = chain.recover(&head).await.unwrap();
    // The floor's parent supplies the floor epoch's verifier material.
    assert!(validated.get_epoch_material(12).is_some());
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
    let mut other = chain.block(96).clone();
    other.timestamp += 1;
    other.txs.clear();
    other.native_targets = None;
    other.receipt_commitment = None;
    let record = Record {
        block: other.encode().to_vec(),
        gas_limit: 100,
        receipts: Vec::new(),
    };
    chain
        .history
        .db
        .put(key(RECORD, 96), borsh::to_vec(&record).unwrap())
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
    // The floor's parent is below the floor: its mappings go too.
    assert_eq!(chain.submission_height(submission(39)), None);
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
    assert_eq!(chain.history.prune_below(60, epoch_length()).unwrap(), 56);
    let floor = |height| HistoryPruned { height, floor: 56 };
    // No epoch material is cached: the floor's epoch reads it from block 55.
    let epochs = LightBlockIndex::new(epoch_length());
    for height in [56, 64, 99] {
        let light = chain.history.light_block(height, &epochs).unwrap();
        assert_eq!(light.height, height);
        assert_eq!(light.epoch, height / EPOCH);
    }
    for height in [1, 40, 54, 55] {
        let error = chain.history.light_block(height, &epochs).unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "proof {height}");
        let error = chain
            .history
            .execution_bounded(IndexQuery::Revision(height), &mut usize::MAX.clone())
            .unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "revision {height}");
        let error = chain.history.stored_block(height).unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "block {height}");
    }
    // An importer may fetch the floor's parent, and nothing lower.
    assert!(
        chain
            .history
            .record_chunk(55, 0, HISTORY_CHUNK_BYTES)
            .is_ok()
    );
    let parent = chain.history.light_block_for_import(55, &epochs).unwrap();
    assert_eq!(parent.height, 55);
    for height in [1, 54] {
        let error = chain
            .history
            .record_chunk(height, 0, HISTORY_CHUNK_BYTES)
            .unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "chunk {height}");
        let error = chain
            .history
            .light_block_for_import(height, &epochs)
            .unwrap_err();
        assert_eq!(pruned(&error), Some(floor(height)), "import proof {height}");
    }
    assert!(
        chain
            .history
            .certified_light_block(30, &epochs)
            .is_err_and(|error| pruned(&error).is_some()),
        "a pruned revision is not pending finality"
    );

    // Rosters read the boundary two epochs back; the oldest the store holds is the floor's parent.
    for epoch in 8..=100 / EPOCH {
        let roster = chain
            .history
            .consensus_roster(Epoch::new(epoch), epoch_length())
            .unwrap();
        assert!(roster.is_some(), "epoch {epoch}");
    }
    let error = chain
        .history
        .consensus_roster(Epoch::new(7), epoch_length())
        .unwrap_err();
    assert_eq!(pruned(&error), Some(floor(47)));

    // A cut needs the block it goes back to.
    let cut = chain.block(50).id().0;
    let error = chain.history.standing(50, &cut, 1).unwrap_err();
    assert_eq!(pruned(&error), Some(floor(50)));
    let error = chain.history.rewind_to(55).unwrap_err();
    assert_eq!(pruned(&error), Some(floor(55)));
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
            floor: 56
        })
    );
}

#[tokio::test]
async fn a_crash_between_prune_batches_leaves_a_floor_matching_the_records() {
    let chain = chain(100);
    let mut batches = 0;
    let error = chain
        .history
        .prune_below_with(90, epoch_length(), |db, batch| {
            batches += 1;
            ensure!(batches <= 3, "injected crash");
            write(db, batch)
        })
        .unwrap_err();
    assert!(error.to_string().contains("injected crash"));
    let chain = chain.reopen();
    assert_eq!(chain.history.floor_height().unwrap(), 24);
    assert!(!chain.holds(RECORD, 22) && chain.holds(RECORD, 23));
    assert!(!chain.holds(CERTIFICATE, 23) && chain.holds(CERTIFICATE, 24));
    assert_eq!(chain.submission_height(submission(23)), None);
    assert_eq!(chain.submission_height(submission(24)), Some(24));
    chain.history.db.delete(VALIDATED).unwrap();
    let chain = chain.reopen();
    let head = chain.head().clone();
    chain.recover(&head).await.unwrap();
    assert_eq!(chain.history.prune_below(90, epoch_length()).unwrap(), 88);
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
    // One pass removes at most 1,024 heights.
    assert_eq!(chain.history.maintain(&retention).unwrap(), 1_024);
    assert_eq!(chain.history.maintain(&retention).unwrap(), 1_296);
    assert_eq!(chain.history.maintain(&retention).unwrap(), 1_296);
}

#[test]
fn a_maintenance_pass_leaves_a_pending_import_alone() {
    let chain = chain(300);
    let retention = HistoryRetention {
        retained: 100,
        interval: NonZeroU64::new(1).unwrap(),
        epoch_length: epoch_length(),
    };
    chain.history.db.put(transfer::IMPORT, [0xff]).unwrap();
    assert_eq!(chain.history.maintain(&retention).unwrap(), 1);
    assert!(chain.holds(RECORD, 1));
    chain.history.db.delete(transfer::IMPORT).unwrap();
    assert_eq!(chain.history.maintain(&retention).unwrap(), 200);
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
