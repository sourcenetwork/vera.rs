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
        .record_anchor(&context(6), &key, &revision(20, 0, 2))
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
        module.record_anchor(&context(2), &key, &revision(30, 1, 1)),
        Err(AnchorError::LowerTerm { latest: 2, term: 1 })
    );
    module
        .record_anchor(&context(3), &key, &revision(30, 3, 1))
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
