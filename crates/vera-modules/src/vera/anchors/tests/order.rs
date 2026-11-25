//! One count orders the anchors of every deployment.

use super::*;

#[test]
fn anchors_of_two_deployments_in_one_block_take_consecutive_numbers() {
    let laptop = key(20);
    let phone = key(21);
    let mut module = registered(&[&laptop, &phone]);
    assert_eq!(module.anchors_recorded(), Ok(0));
    let block = context(7);
    let first = module
        .record_anchor(&block, &deployment_id(&phone), &revision(10, 0, 1))
        .unwrap()
        .record;
    let second = module
        .record_anchor(&block, &deployment_id(&laptop), &revision(40, 0, 2))
        .unwrap()
        .record;
    let third = module
        .record_anchor(&block, &deployment_id(&phone), &descendant(11, 0, 3, 10, 1))
        .unwrap()
        .record;
    assert_eq!(
        [first.order, second.order, third.order],
        [1, 2, 3],
        "execution order, not deployment or height"
    );
    assert_eq!([first.sequence, second.sequence, third.sequence], [1, 1, 2]);
    assert_eq!(module.anchors_recorded(), Ok(3));
    assert_eq!(
        module
            .anchor_entry(&deployment_id(&phone), 2)
            .unwrap()
            .map(|entry| entry.order),
        Some(3)
    );

    // A refusal and a resubmission take no number.
    assert!(
        module
            .record_anchor(&context(8), &deployment_id(&laptop), &revision(39, 0, 4))
            .is_err()
    );
    let again = module
        .record_anchor(&context(8), &deployment_id(&laptop), &revision(40, 0, 2))
        .unwrap();
    assert!(!again.recorded);
    assert_eq!(again.record.order, 2);
    assert_eq!(module.anchors_recorded(), Ok(3));
    let next = module
        .record_anchor(
            &context(8),
            &deployment_id(&laptop),
            &descendant(41, 0, 5, 40, 2),
        )
        .unwrap()
        .record;
    assert_eq!(next.order, 4);
}

#[test]
fn a_term_that_voids_anchors_leaves_their_numbers() {
    let key = key(22);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(1), &deployment, &revision(10, 0, 1))
        .unwrap()
        .record;
    let voided = module
        .record_anchor(&context(2), &deployment, &descendant(20, 0, 2, 10, 1))
        .unwrap()
        .record;
    let taken = module
        .record_term(
            &context(3),
            &deployment,
            &VerifiedTerm {
                term: 1,
                holder: B256::repeat_byte(0xd0),
                cut_height: 10,
                cut_block: B256::repeat_byte(1),
            },
        )
        .unwrap();
    assert!(taken.supersedes(voided.sequence, voided.height, &voided.block_hash));
    assert_eq!(module.anchors_recorded(), Ok(2));
    assert_eq!(module.latest_anchor(&deployment).unwrap(), Some(voided));
    assert_eq!(
        module
            .anchor_entry(&deployment, 1)
            .unwrap()
            .map(|entry| entry.order),
        Some(first.order)
    );
    let continued = module
        .record_anchor(&context(4), &deployment, &descendant(15, 1, 3, 10, 1))
        .unwrap()
        .record;
    assert_eq!((continued.sequence, continued.order), (3, 3));
    assert_eq!(
        module
            .anchor_entry(&deployment, 2)
            .unwrap()
            .map(|entry| entry.order),
        Some(2)
    );
}

#[test]
fn a_stored_count_is_eight_nonzero_bytes() {
    assert_eq!(decode_order(&5u64.to_be_bytes()), Ok(5));
    assert_eq!(
        decode_order(&0u64.to_be_bytes()),
        Err(AnchorError::MalformedRecord)
    );
    assert_eq!(decode_order(&[1; 7]), Err(AnchorError::MalformedRecord));
    let mut module = VeraModule::new();
    module.store.put(ANCHOR_ORDER_KEY, vec![1; 9]);
    assert_eq!(module.anchors_recorded(), Err(AnchorError::MalformedRecord));
}
