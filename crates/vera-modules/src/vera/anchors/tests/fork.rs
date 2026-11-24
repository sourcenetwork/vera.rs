//! Certified blocks that leave the anchored history.

use super::*;

#[test]
fn a_block_that_leaves_the_anchored_history_is_recorded_as_a_fork() {
    let key = key(11);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    assert_eq!(
        module.record_fork(&context(1), &deployment, &revision(20, 0, 2)),
        Err(AnchorError::NoAnchor)
    );
    module
        .record_anchor(&context(1), &deployment_id(&key), &revision(20, 0, 1))
        .unwrap();

    // Another block at the anchored height.
    let same_height = module
        .record_fork(&context(2), &deployment_id(&key), &revision(20, 0, 2))
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
        module.record_fork(&context(3), &deployment_id(&key), &revision(20, 0, 2)),
        Err(AnchorError::ForkRecorded)
    );

    // A block above it whose ancestor at the anchored height is another block.
    let above = module
        .record_fork(
            &context(3),
            &deployment_id(&key),
            &descendant(25, 0, 5, 20, 2),
        )
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
        module.record_fork(&context(4), &deployment_id(&key), &revision(20, 0, 1)),
        not_a_fork(20)
    );
    assert_eq!(
        module.record_fork(
            &context(4),
            &deployment_id(&key),
            &descendant(30, 0, 6, 20, 1)
        ),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(&context(4), &deployment_id(&key), &revision(30, 0, 7)),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(
            &context(4),
            &deployment_id(&key),
            &descendant(30, 0, 7, 19, 2)
        ),
        not_a_fork(30)
    );
    assert_eq!(
        module.record_fork(
            &context(4),
            &deployment_id(&key),
            &descendant(19, 0, 8, 18, 2)
        ),
        not_a_fork(19)
    );
    // The latest anchor is unchanged, and the next one still extends it.
    module
        .record_anchor(
            &context(5),
            &deployment_id(&key),
            &descendant(30, 0, 6, 20, 1),
        )
        .unwrap();
}
