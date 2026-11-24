use alloy_primitives::B256;

use super::*;
use crate::types::Timestamp;

fn context(height: u64) -> BlockExecCtx {
    BlockExecCtx {
        timestamp: Timestamp {
            seconds: 1_800_000_000,
            block_height: height,
        },
        ..BlockExecCtx::default()
    }
}

fn key(seed: u8) -> Vec<u8> {
    vec![seed; CONSENSUS_KEY_BYTES]
}

fn revision(height: u64, term: u64, root: u8) -> VerifiedRevision {
    VerifiedRevision {
        height,
        block_hash: B256::repeat_byte(root),
        term,
        timestamp: 1_700_000_000 + height,
        module_state_root: B256::repeat_byte(root),
        ancestor: None,
    }
}

/// A revision the caller proved to descend from the block `ancestor` at `from`.
fn descendant(height: u64, term: u64, root: u8, from: u64, ancestor: u8) -> VerifiedRevision {
    VerifiedRevision {
        ancestor: Some((from, B256::repeat_byte(ancestor))),
        ..revision(height, term, root)
    }
}

#[test]
fn anchors_advance_in_order_and_keep_the_latest_revision() {
    let key = key(1);
    let mut module = VeraModule::new();
    let first = module
        .record_anchor(&context(5), &key, &revision(10, 0, 1))
        .unwrap();
    assert!(first.recorded);
    assert_eq!(first.record.sequence, 1);
    assert_eq!(first.record.height, 10);
    assert_eq!(first.record.module_state_root, B256::repeat_byte(1));
    assert_eq!(first.record.anchored_at, 5);
    assert_eq!(first.record.deployment, deployment_id(&key));
    assert_eq!(first.record.consensus_key.as_ref(), key.as_slice());

    let second = module
        .record_anchor(&context(6), &key, &descendant(20, 0, 2, 10, 1))
        .unwrap();
    assert_eq!(second.record.sequence, 2);
    assert_eq!(
        module.latest_anchor(&second.record.deployment).unwrap(),
        Some(second.record)
    );
}

#[test]
fn an_anchor_that_goes_backwards_is_refused() {
    let key = key(2);
    let mut module = VeraModule::new();
    module
        .record_anchor(&context(1), &key, &revision(20, 0, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &key, &revision(19, 0, 1)),
        Err(AnchorError::NotNewer {
            latest: 20,
            height: 19
        })
    );
}

#[test]
fn a_second_history_at_an_anchored_height_cannot_displace_the_first() {
    let key = key(3);
    let mut module = VeraModule::new();
    let first = module
        .record_anchor(&context(1), &key, &revision(20, 0, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &key, &revision(20, 0, 2)),
        Err(AnchorError::NotNewer {
            latest: 20,
            height: 20
        })
    );
    assert_eq!(
        module.latest_anchor(&first.record.deployment).unwrap(),
        Some(first.record.clone())
    );

    let again = module
        .record_anchor(&context(3), &key, &revision(20, 0, 1))
        .unwrap();
    assert!(!again.recorded);
    assert_eq!(again.record, first.record);
}

#[test]
fn a_lower_term_is_refused() {
    let key = key(4);
    let mut module = VeraModule::new();
    module
        .record_anchor(&context(1), &key, &revision(20, 2, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &key, &descendant(30, 1, 3, 20, 1)),
        Err(AnchorError::LowerTerm { latest: 2, term: 1 })
    );
    module
        .record_anchor(&context(3), &key, &descendant(30, 3, 3, 20, 1))
        .unwrap();
}

#[test]
fn deployments_keep_separate_anchors() {
    let mut module = VeraModule::new();
    module
        .record_anchor(&context(1), &key(5), &revision(20, 0, 1))
        .unwrap();
    let other = module
        .record_anchor(&context(2), &key(50), &revision(10, 0, 1))
        .unwrap();
    assert!(other.recorded);
    assert_eq!(other.record.sequence, 1);
    assert_ne!(deployment_id(&key(5)), deployment_id(&key(50)));
}

#[test]
fn a_key_of_the_wrong_length_is_refused() {
    let mut module = VeraModule::new();
    let mut short = key(6);
    short.truncate(10);
    assert_eq!(
        module.record_anchor(&context(1), &short, &revision(10, 0, 1)),
        Err(AnchorError::InvalidConsensusKey)
    );
    assert_eq!(module.latest_anchor(&deployment_id(&short)), Ok(None));
}

#[test]
fn stored_records_must_name_their_deployment() {
    let mut module = VeraModule::new();
    let anchored = module
        .record_anchor(&context(1), &key(8), &revision(10, 0, 1))
        .unwrap();
    let bytes = anchored.record.encode();
    assert_eq!(
        AnchorRecord::decode(&anchored.record.deployment, &bytes).unwrap(),
        anchored.record
    );
    assert_eq!(
        AnchorRecord::decode(&B256::repeat_byte(1), &bytes),
        Err(AnchorError::MalformedRecord)
    );

    let mut foreign_key = anchored.record.clone();
    foreign_key.consensus_key = key(9).into();
    assert_eq!(
        AnchorRecord::decode(&foreign_key.deployment, &foreign_key.encode()),
        Err(AnchorError::MalformedRecord)
    );

    let mut short_key = anchored.record;
    short_key.consensus_key = vec![8; 10].into();
    short_key.deployment = deployment_id(&short_key.consensus_key);
    assert_eq!(
        AnchorRecord::decode(&short_key.deployment, &short_key.encode()),
        Err(AnchorError::MalformedRecord)
    );
}

#[test]
fn an_anchor_must_descend_from_the_latest_one() {
    let key = key(10);
    let mut module = VeraModule::new();
    let first = module
        .record_anchor(&context(1), &key, &revision(20, 0, 1))
        .unwrap();
    let refused = Err(AnchorError::NotDescendant {
        latest: 20,
        height: 30,
    });
    // No ancestor, another block at the anchored height, and the anchored block at another height.
    assert_eq!(
        module.record_anchor(&context(2), &key, &revision(30, 0, 3)),
        refused
    );
    assert_eq!(
        module.record_anchor(&context(2), &key, &descendant(30, 0, 3, 20, 9)),
        refused
    );
    assert_eq!(
        module.record_anchor(&context(2), &key, &descendant(30, 0, 3, 19, 1)),
        refused
    );
    assert_eq!(
        module.latest_anchor(&first.record.deployment).unwrap(),
        Some(first.record)
    );
    let second = module
        .record_anchor(&context(2), &key, &descendant(30, 0, 3, 20, 1))
        .unwrap();
    assert_eq!(second.record.sequence, 2);
    // The next anchor extends the second one, not the first.
    assert_eq!(
        module.record_anchor(&context(3), &key, &descendant(40, 0, 4, 20, 1)),
        Err(AnchorError::NotDescendant {
            latest: 30,
            height: 40
        })
    );
}

#[test]
fn a_block_that_leaves_the_anchored_history_is_recorded_as_a_fork() {
    let key = key(11);
    let deployment = deployment_id(&key);
    let mut module = VeraModule::new();
    assert_eq!(
        module.record_fork(&context(1), &key, &revision(20, 0, 2)),
        Err(AnchorError::NoAnchor)
    );
    module
        .record_anchor(&context(1), &key, &revision(20, 0, 1))
        .unwrap();

    // Another block at the anchored height.
    let same_height = module
        .record_fork(&context(2), &key, &revision(20, 0, 2))
        .unwrap();
    assert_eq!(
        (
            same_height.sequence,
            same_height.anchored_height,
            same_height.height
        ),
        (1, 20, 20)
    );
    assert_eq!(same_height.anchored_block, B256::repeat_byte(1));
    assert_eq!(same_height.ancestor, B256::repeat_byte(2));
    assert_eq!(same_height.reported_at, 2);
    assert_eq!(
        module.record_fork(&context(3), &key, &revision(20, 0, 2)),
        Err(AnchorError::ForkRecorded)
    );

    // A block above it whose ancestor at the anchored height is another block.
    let above = module
        .record_fork(&context(3), &key, &descendant(25, 0, 5, 20, 2))
        .unwrap();
    assert_eq!((above.height, above.ancestor), (25, B256::repeat_byte(2)));
    assert_eq!(
        module.forks(&deployment).unwrap(),
        vec![same_height, above.clone()]
    );
    assert_eq!(
        ForkRecord::decode(&deployment, &above.encode()).unwrap(),
        above
    );
    assert_eq!(
        ForkRecord::decode(&B256::ZERO, &above.encode()),
        Err(AnchorError::MalformedRecord)
    );

    let not_a_fork = |height| Err(AnchorError::NotAFork { latest: 20, height });
    // The anchored block, a descendant of it, an unproven block and one below the anchor.
    assert_eq!(
        module.record_fork(&context(4), &key, &revision(20, 0, 1)),
        not_a_fork(20)
    );
    assert_eq!(
        module.record_fork(&context(4), &key, &descendant(30, 0, 6, 20, 1)),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(&context(4), &key, &revision(30, 0, 7)),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(&context(4), &key, &descendant(30, 0, 7, 19, 2)),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(&context(4), &key, &descendant(19, 0, 8, 18, 2)),
        not_a_fork(19)
    );
    // The latest anchor is unchanged, and the next one still extends it.
    module
        .record_anchor(&context(5), &key, &descendant(30, 0, 6, 20, 1))
        .unwrap();
}
