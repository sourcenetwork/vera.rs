use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_domain::testing::TestDeployment;
use vera_modules::vera::anchors::AnchorRecord;

use super::{
    AnchoringError, TermRecord, deployment_id,
    snapshot::{ensure_kept, ensure_not_superseded},
};

fn record(sequence: u64, block: u8) -> AnchorRecord {
    let key = TestDeployment::new(31).key();
    AnchorRecord {
        deployment: deployment_id(&key),
        consensus_key: key.encode().to_vec().into(),
        sequence,
        height: sequence * 10,
        block_hash: B256::repeat_byte(block),
        term: 0,
        timestamp: 0,
        module_state_root: B256::ZERO,
        anchored_at: sequence,
    }
}

#[test]
fn a_snapshot_of_an_older_anchor_is_stale_once_a_newer_one_is_known() {
    let held = record(2, 2);
    ensure_not_superseded(&held, &record(2, 2)).unwrap();
    ensure_not_superseded(&held, &record(1, 1)).unwrap();
    assert!(matches!(
        ensure_not_superseded(&held, &record(3, 3)),
        Err(AnchoringError::Stale { held: 2, latest: 3 })
    ));
    assert!(matches!(
        ensure_not_superseded(&held, &record(2, 9)),
        Err(AnchoringError::Conflict(2))
    ));
    let mut other = record(5, 5);
    other.deployment = B256::repeat_byte(1);
    assert!(ensure_not_superseded(&held, &other).is_err());
}

#[test]
fn a_snapshot_whose_anchor_a_term_voided_is_superseded() {
    let term = |term, cut_height, sequence| TermRecord {
        deployment: record(1, 1).deployment,
        term,
        holder: B256::ZERO,
        cut_height,
        cut_block: B256::repeat_byte(7),
        sequence,
        recorded_at: 9,
    };
    // Anchors 1 to 3 at heights 10, 20 and 30; term 1 cut at 15 when 3 was the latest.
    let terms = [term(1, 15, 3), term(2, 45, 5)];
    ensure_kept(&record(1, 1), &terms).unwrap();
    for sequence in [2, 3] {
        assert!(matches!(
            ensure_kept(&record(sequence, sequence as u8), &terms),
            Err(AnchoringError::Superseded { held, term: 1 }) if held == sequence
        ));
    }
    // An anchor recorded in term 1, and one recorded after term 2, are kept by both.
    ensure_kept(&record(4, 4), &terms).unwrap();
    ensure_kept(&record(6, 6), &terms).unwrap();
    // The second term voids an anchor of the first above its cut.
    assert!(matches!(
        ensure_kept(&record(5, 5), &terms),
        Err(AnchoringError::Superseded { held: 5, term: 2 })
    ));
    ensure_kept(&record(2, 2), &[]).unwrap();
    let mut foreign = term(1, 15, 3);
    foreign.deployment = B256::repeat_byte(1);
    assert!(ensure_kept(&record(1, 1), &[foreign]).is_err());
}
