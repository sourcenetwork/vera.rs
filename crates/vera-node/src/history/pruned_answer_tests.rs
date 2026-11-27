//! What a lookup by submission answers once the floor has passed its revision.

use vera_indexer::IndexQuery;

use super::*;
use crate::history::retention::fixture::{Chain, chain, epoch_length, pruned, submission};

/// The answer for `hash`: the revision holding it, nothing, or the pruned error.
type Answer = std::result::Result<Option<u64>, HistoryPruned>;

fn execution(chain: &Chain, hash: B256, after: Option<u64>) -> Answer {
    let mut remaining_bytes = usize::MAX;
    chain
        .history
        .execution_bounded(IndexQuery::Submission { hash, after }, &mut remaining_bytes)
        .map(|found| found.map(|execution| execution.block.height))
        .map_err(|error| pruned(&error).expect("a pruned read"))
}

fn proof(chain: &Chain, hash: B256, after: Option<u64>) -> Answer {
    let epochs = LightBlockIndex::new(epoch_length());
    chain
        .history
        .receipt_proof(hash, after, &epochs)
        .map(|found| found.map(|response| response.revision.height))
        .map_err(|error| pruned(&error).expect("a pruned read"))
}

/// Every answer about a pruned, a retained and an unknown submission, by
/// both lookups, without a revision and with ones around the floor of 48.
fn answers(chain: &Chain) -> Vec<Answer> {
    let unknown = B256::repeat_byte(0xee);
    let mut answers = Vec::new();
    for hash in [submission(10), submission(47), submission(70), unknown] {
        for after in [None, Some(0), Some(9), Some(46), Some(47), Some(99)] {
            answers.push(execution(chain, hash, after));
            answers.push(proof(chain, hash, after));
        }
    }
    answers
}

#[test]
fn a_pruned_submission_reads_the_same_whether_or_not_its_mapping_is_swept() {
    let chain = chain(100);
    let mut writes = 0;
    chain
        .history
        .prune_below_with(50, epoch_length(), |db, batch| {
            writes += 1;
            ensure!(writes == 1, "the sweep is interrupted");
            write(db, batch)
        })
        .unwrap_err();
    // The floor is raised and the mapping still names the pruned record.
    assert_eq!(chain.history.floor_height().unwrap(), 48);
    assert_eq!(chain.submission_height(submission(10)), Some(10));
    let unswept = answers(&chain);

    assert_eq!(chain.history.prune_below(50, epoch_length()).unwrap(), 48);
    assert_eq!(chain.submission_height(submission(10)), None);
    assert_eq!(answers(&chain), unswept);
}

#[test]
fn a_pruned_submission_is_not_found_and_is_refused_to_a_caller_that_knows_it_was_admitted() {
    let chain = chain(100);
    chain.history.prune_below(50, epoch_length()).unwrap();
    let floor = |height| Err(HistoryPruned { height, floor: 48 });
    for lookup in [execution, proof] {
        for hash in [submission(10), B256::repeat_byte(0xee)] {
            assert_eq!(lookup(&chain, hash, None), Ok(None));
            // Revisions that may have held it are pruned.
            assert_eq!(lookup(&chain, hash, Some(0)), floor(1));
            assert_eq!(lookup(&chain, hash, Some(9)), floor(10));
            assert_eq!(lookup(&chain, hash, Some(46)), floor(47));
            // Every revision above 47 is retained and none holds it.
            assert_eq!(lookup(&chain, hash, Some(47)), Ok(None));
            assert_eq!(lookup(&chain, hash, Some(99)), Ok(None));
        }
        // A retained submission is served whatever the caller knows.
        for after in [None, Some(0), Some(9), Some(69)] {
            assert_eq!(lookup(&chain, submission(70), after), Ok(Some(70)));
        }
    }
}

#[test]
fn an_unpruned_store_refuses_no_lookup() {
    let chain = chain(20);
    for lookup in [execution, proof] {
        assert_eq!(lookup(&chain, B256::repeat_byte(0xee), Some(0)), Ok(None));
        assert_eq!(lookup(&chain, submission(10), Some(0)), Ok(Some(10)));
    }
}
