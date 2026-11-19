//! Importing history from a store that has pruned it, finishing at a floor.

use super::*;
use crate::history::retention::fixture::{
    SIGNER, chain, chain_with, epoch_length, holds, pruned, recover, revision, submission,
};
use vera_domain::LightBlock;

const LIMITS: HistoryLimits = HistoryLimits {
    record_bytes: 1 << 20,
    logs: 100,
};

/// The record at `height` and its finality proof, as a peer serves them.
fn fetch(source: &FinalizedHistory, height: u64) -> Result<(Vec<u8>, LightBlock)> {
    let epochs = LightBlockIndex::new(epoch_length());
    let mut bytes = Vec::new();
    loop {
        let chunk = source.record_chunk(height, bytes.len() as u64, HISTORY_CHUNK_BYTES)?;
        bytes.extend(chunk.bytes);
        if bytes.len() as u64 == chunk.total {
            break;
        }
    }
    Ok((bytes, source.light_block_for_import(height, &epochs)?))
}

/// Import from `source` through `anchor`, as the snapshot handoff does with
/// one peer: down to the destination's head, or to a floor where the peer
/// refuses a pruned record. Returns the adopted floor, if any.
fn import(
    source: &FinalizedHistory,
    destination: &FinalizedHistory,
    anchor: u64,
) -> Result<Option<u64>> {
    let epochs = LightBlockIndex::new(epoch_length());
    let selected = source.light_block_for_import(anchor, &epochs)?;
    let (_, trusted) = transfer::tests::certify(&revision(1, BlockId(B256::ZERO)).0, SIGNER);
    destination.begin_import(&selected, &trusted)?;
    while let Some((height, _)) = destination.import_next()? {
        match fetch(source, height) {
            Ok((bytes, proof)) => destination.import_record(&bytes, LIMITS, &proof)?,
            Err(error) if pruned(&error).is_some() => {
                return destination.finish_import_at_floor(epoch_length()).map(Some);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

#[tokio::test]
async fn an_empty_store_imports_from_a_pruned_peer_and_adopts_its_floor() {
    let source = chain_with(60, true);
    assert_eq!(source.history.prune_below(42, epoch_length()).unwrap(), 40);
    let destination = chain(0);
    let floor = import(&source.history, &destination.history, 60).unwrap();
    assert_eq!(floor, Some(40));
    // A crash before the recovery that publishes the import leaves it complete.
    let destination = destination.reopen();
    assert!(destination.history.import_next().unwrap().is_none());
    let anchor = source.block(60).clone();
    destination.recover(&anchor).await.unwrap();
    assert_eq!(destination.history.floor_height().unwrap(), 40);
    assert_eq!(destination.history.head_height(), 60);
    for height in 1..=60 {
        assert_eq!(
            destination.holds(RECORD, height),
            height >= 39,
            "record {height}"
        );
    }
    let epochs = LightBlockIndex::new(epoch_length());
    assert!(destination.history.light_block(40, &epochs).is_ok());
    let error = destination.history.light_block(39, &epochs).unwrap_err();
    assert_eq!(pruned(&error).map(|pruned| pruned.floor), Some(40));
    let found = destination.history.execution_by_submission(submission(45));
    assert_eq!(found.unwrap().unwrap().block.height, 45);
    // It serves the same window to the next importer.
    let next = chain(0);
    assert_eq!(
        import(&destination.history, &next.history, 60).unwrap(),
        Some(40)
    );
}

#[tokio::test]
async fn a_store_with_older_history_of_its_own_ends_with_one_window() {
    let source = chain_with(60, true);
    source.history.prune_below(42, epoch_length()).unwrap();
    let destination = chain(10);
    assert!(destination.submission_height(submission(10)).is_some());
    let floor = import(&source.history, &destination.history, 60).unwrap();
    assert_eq!(floor, Some(40));
    destination.recover(source.block(60)).await.unwrap();
    for height in 1..=60 {
        assert_eq!(
            destination.holds(RECORD, height),
            height >= 39,
            "record {height}"
        );
        assert_eq!(
            holds(&destination.history, CERTIFICATE, height),
            height >= 40,
            "certificate {height}"
        );
    }
    assert_eq!(destination.submission_height(submission(10)), None);
    assert_eq!(destination.submission_height(submission(50)), Some(50));
    // The window prunes and recovers like any other.
    assert_eq!(
        destination.history.prune_below(50, epoch_length()).unwrap(),
        48
    );
    let reopened = destination.reopen();
    reopened.history.db.delete(VALIDATED).unwrap();
    recover(&reopened.history, &reopened.genesis, source.block(60))
        .await
        .unwrap();
}

#[test]
fn an_import_does_not_finish_above_the_anchors_epoch() {
    let source = chain_with(60, true);
    let destination = chain(0);
    let epochs = LightBlockIndex::new(epoch_length());
    let selected = source.history.light_block(60, &epochs).unwrap();
    let (_, trusted) = transfer::tests::certify(&revision(1, BlockId(B256::ZERO)).0, SIGNER);
    destination
        .history
        .begin_import(&selected, &trusted)
        .unwrap();
    for height in [60, 59, 58] {
        let (bytes, proof) = fetch(&source.history, height).unwrap();
        destination
            .history
            .import_record(&bytes, LIMITS, &proof)
            .unwrap();
    }
    // Block 57 is missing: the floor would be 64, above the anchor's epoch at 56.
    let error = destination
        .history
        .finish_import_at_floor(epoch_length())
        .unwrap_err();
    assert_eq!(
        pruned(&error),
        Some(HistoryPruned {
            height: 57,
            floor: 64
        })
    );
    assert_eq!(destination.history.import_next().unwrap().unwrap().0, 57);
    assert_eq!(destination.history.floor_height().unwrap(), 1);
}
