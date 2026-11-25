//! The append-only history of a deployment's anchors.

use super::*;

#[test]
fn every_anchor_stays_in_the_deployments_history() {
    let other = key(13);
    let key = key(12);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key, &other]);
    let first = module
        .record_anchor(&context(1), &deployment_id(&key), &revision(10, 0, 1))
        .unwrap();
    let second = module
        .record_anchor(
            &context(2),
            &deployment_id(&key),
            &descendant(20, 0, 2, 10, 1),
        )
        .unwrap();
    // A resubmission and a refusal add nothing.
    module
        .record_anchor(
            &context(3),
            &deployment_id(&key),
            &descendant(20, 0, 2, 10, 1),
        )
        .unwrap();
    module
        .record_anchor(&context(3), &deployment_id(&key), &revision(30, 0, 3))
        .unwrap_err();
    module
        .record_anchor(&context(4), &deployment_id(&other), &revision(5, 0, 9))
        .unwrap();

    let entries: Vec<_> = module
        .store
        .prefix_scan(&anchor_history_prefix(&deployment))
        .iter()
        .map(|(stored, bytes)| AnchorEntry::decode(&deployment, stored, bytes).unwrap())
        .collect();
    assert_eq!(
        entries,
        [
            AnchorEntry::from(&first.record),
            AnchorEntry::from(&second.record)
        ]
    );
    assert_eq!(
        (
            entries[0].sequence,
            entries[0].height,
            entries[0].anchored_at
        ),
        (1, 10, 1)
    );
    assert_eq!(entries[1].module_state_root, B256::repeat_byte(2));
    assert_eq!(
        module.anchor_entry(&deployment, 2).unwrap().as_ref(),
        Some(&entries[1])
    );
    assert_eq!(module.anchor_entry(&deployment, 3), Ok(None));
    assert!(entries[1].encode().len() <= MAX_ANCHOR_ENTRY_BYTES);

    // An entry is the one its key names, and the latest anchor is no entry.
    let bytes = entries[0].encode();
    assert_eq!(
        AnchorEntry::decode(&deployment, &anchor_entry_key(&deployment, 2), &bytes),
        Err(AnchorError::MalformedRecord)
    );
    assert_eq!(
        AnchorEntry::decode(&B256::ZERO, &anchor_entry_key(&B256::ZERO, 1), &bytes),
        Err(AnchorError::MalformedRecord)
    );
    assert!(!anchor_key(&deployment).starts_with(&anchor_history_prefix(&deployment)));
}
