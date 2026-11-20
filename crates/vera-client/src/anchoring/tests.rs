use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_domain::testing::TestDeployment;
use vera_modules::vera::anchors::AnchorRecord;

use super::{AnchoringError, deployment_id, snapshot::ensure_not_superseded};

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
