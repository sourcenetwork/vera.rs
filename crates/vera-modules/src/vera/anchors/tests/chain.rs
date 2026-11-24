//! Anchors extend the tip of their deployment's chain.

use super::*;

#[test]
fn anchors_advance_in_order_and_keep_the_latest_revision() {
    let key = key(1);
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(5), &deployment_id(&key), &revision(10, 0, 1))
        .unwrap();
    assert!(first.recorded);
    assert_eq!(first.record.sequence, 1);
    assert_eq!(first.record.height, 10);
    assert_eq!(first.record.module_state_root, B256::repeat_byte(1));
    assert_eq!(first.record.anchored_at, 5);
    assert_eq!(first.record.deployment, deployment_id(&key));
    assert_eq!(first.record.consensus_key.as_ref(), key.as_slice());

    let second = module
        .record_anchor(
            &context(6),
            &deployment_id(&key),
            &descendant(20, 0, 2, 10, 1),
        )
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
    let mut module = registered(&[&key]);
    module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &deployment_id(&key), &revision(19, 0, 1)),
        Err(AnchorError::NotNewer {
            latest: 20,
            height: 19
        })
    );
}

#[test]
fn a_second_history_at_an_anchored_height_cannot_displace_the_first() {
    let key = key(3);
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &deployment_id(&key), &revision(20, 0, 2)),
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
        .record_anchor(&context(3), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    assert!(!again.recorded);
    assert_eq!(again.record, first.record);
}

#[test]
fn deployments_keep_separate_anchors() {
    let mut module = registered(&[&key(5), &key(50)]);
    module
        .record_anchor(&context(1), &deployment_id(&key(5)), &revision(20, 0, 1))
        .unwrap();
    let other = module
        .record_anchor(&context(2), &deployment_id(&key(50)), &revision(10, 0, 1))
        .unwrap();
    assert!(other.recorded);
    assert_eq!(other.record.sequence, 1);
    assert_ne!(deployment_id(&key(5)), deployment_id(&key(50)));
}

#[test]
fn stored_records_must_name_their_deployment() {
    let mut module = registered(&[&key(8)]);
    let anchored = module
        .record_anchor(&context(1), &deployment_id(&key(8)), &revision(10, 0, 1))
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
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();
    let refused = Err(AnchorError::NotDescendant {
        latest: 20,
        height: 30,
    });
    // No ancestor, another block at the anchored height, and the anchored block at another height.
    assert_eq!(
        module.record_anchor(&context(2), &deployment_id(&key), &revision(30, 0, 3)),
        refused
    );
    assert_eq!(
        module.record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(30, 0, 3, 20, 9)
        ),
        refused
    );
    assert_eq!(
        module.record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(30, 0, 3, 19, 1)
        ),
        refused
    );
    assert_eq!(
        module.latest_anchor(&first.record.deployment).unwrap(),
        Some(first.record)
    );
    let second = module
        .record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(30, 0, 3, 20, 1),
        )
        .unwrap();
    assert_eq!(second.record.sequence, 2);
    // The next anchor extends the second one, not the first.
    assert_eq!(
        module.record_anchor(
            &context(3),
            &deployment_id(&key),
            &descendant(40, 0, 4, 20, 1)
        ),
        Err(AnchorError::NotDescendant {
            latest: 30,
            height: 40
        })
    );
}
