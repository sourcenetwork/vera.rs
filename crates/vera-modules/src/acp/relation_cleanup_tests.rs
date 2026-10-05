use super::super::retirement_cleanup::{MAX_BYTES, MAX_ITEMS};
use super::*;
use acp::Subject;

const ORIGINAL: &str = "name: generations\nresources:\n  - name: file\n    relations:\n      - name: reader\n      - name: viewer\n  - name: group\n    relations:\n      - name: member\n";
const REMOVED: &str = "name: generations\nresources:\n  - name: file\n    relations:\n      - name: viewer\n  - name: group\n";

fn actor() -> Did {
    Did::new("did:key:owner").unwrap()
}
fn block(height: u64) -> BlockExecCtx {
    BlockExecCtx {
        timestamp: Timestamp {
            seconds: height,
            block_height: height,
        },
        ..Default::default()
    }
}
fn restore(module: &AcpModule) -> AcpModule {
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    restored.validate_restored_state().unwrap();
    restored
}
fn rows(module: &AcpModule, policy: &str) -> usize {
    module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(policy))
        .count()
}
fn put_row(module: &mut AcpModule, policy: &str, index: usize) -> Vec<u8> {
    let definition = module.query_policy(policy).unwrap();
    let relationship = Relationship::new(
        "file",
        format!("item-{index}"),
        if index.is_multiple_of(2) {
            "reader"
        } else {
            "viewer"
        },
        Subject::entity_set("group", "staff", "member"),
    );
    let record = RelationshipRecord {
        generations: definition.relations.pair(&relationship).unwrap(),
        relationship,
        policy_id: policy.into(),
        archived: index.is_multiple_of(3),
        supplied_metadata: Default::default(),
        metadata: definition.metadata,
    };
    relationship_mutations::put(&mut module.store, &record).unwrap();
    keys::relationship_generation_key(
        policy,
        record.generations,
        &keys::relationship_storage_key(&record.relationship),
    )
}
fn setup(module: &mut AcpModule, count: usize) -> String {
    let policy = module
        .create_policy(&actor(), ORIGINAL, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    for index in 0..count {
        put_row(module, &policy, index);
    }
    policy
}
fn remove(module: &mut AcpModule, policy: &str) -> u64 {
    module
        .edit_policy(&actor(), policy, REMOVED, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .0
}

#[test]
fn cleanup_drains_target_and_incoming_rows_without_removing_recreated_names() {
    let mut module = AcpModule::new();
    let policy = setup(&mut module, MAX_ITEMS + 3);
    let old_keys: Vec<_> = module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(&policy))
        .map(|(key, _)| key.to_vec())
        .collect();
    assert_eq!(remove(&mut module, &policy), (MAX_ITEMS + 3) as u64);
    assert_eq!(rows(&module, &policy), MAX_ITEMS + 3);
    module = restore(&module);
    assert_eq!(
        module
            .edit_policy(&actor(), &policy, ORIGINAL, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .0,
        0
    );
    let fresh = put_row(&mut module, &policy, 0);
    assert!(!old_keys.contains(&fresh));
    for height in 1..12 {
        module.end_blocker(&block(height)).unwrap();
        module = restore(&module);
        if module
            .store
            .prefix_iter(edits::QUEUE_PREFIX)
            .next()
            .is_none()
        {
            break;
        }
    }
    assert!(
        module
            .store
            .prefix_iter(edits::QUEUE_PREFIX)
            .next()
            .is_none()
    );
    assert!(
        module
            .store
            .prefix_iter(&edits::retired_relation_prefix(&policy))
            .next()
            .is_none()
    );
    assert_eq!(rows(&module, &policy), 1);
    assert!(module.store.has(&fresh));
    assert!(old_keys.iter().all(|key| !module.store.has(key)));
}

#[test]
fn policy_and_generation_cleanup_share_one_budget_and_both_make_progress() {
    let mut module = AcpModule::new();
    let edited = setup(&mut module, MAX_ITEMS * 2);
    let deleted = setup(&mut module, MAX_ITEMS * 2);
    remove(&mut module, &edited);
    module.delete_policy(&actor(), &deleted).unwrap();
    let initial = [rows(&module, &edited), rows(&module, &deleted)];
    for height in [1, 2] {
        let before = rows(&module, &edited) + rows(&module, &deleted);
        module.end_blocker(&block(height)).unwrap();
        let after = rows(&module, &edited) + rows(&module, &deleted);
        assert!(before - after <= MAX_ITEMS);
        module = restore(&module);
    }
    assert!(rows(&module, &edited) < initial[0]);
    assert!(rows(&module, &deleted) < initial[1]);
}

#[test]
fn whole_policy_retirement_owns_pending_generation_jobs_and_removes_all_metadata() {
    let mut module = AcpModule::new();
    let policy = setup(&mut module, MAX_ITEMS + 1);
    remove(&mut module, &policy);
    module.delete_policy(&actor(), &policy).unwrap();
    // Generation jobs may disappear while their descriptors are still required by physical rows.
    module
        .collect_retired_relations(&mut Budget::new())
        .unwrap();
    assert!(
        module
            .store
            .prefix_iter(edits::QUEUE_PREFIX)
            .next()
            .is_none()
    );
    assert!(
        module
            .store
            .prefix_iter(&edits::retired_relation_prefix(&policy))
            .next()
            .is_some()
    );
    module = restore(&module);
    for height in 1..12 {
        module.end_blocker(&block(height)).unwrap();
        module = restore(&module);
        if !module.policy_cleanup_pending(&policy).unwrap() {
            break;
        }
    }
    assert!(!module.policy_cleanup_pending(&policy).unwrap());
    assert_eq!(rows(&module, &policy), 0);
    assert!(
        module
            .store
            .prefix_iter(&relationship_index::policy_prefix(&policy))
            .next()
            .is_none()
    );
    assert!(
        module
            .store
            .prefix_iter(edits::QUEUE_PREFIX)
            .next()
            .is_none()
    );
}

#[test]
fn maximum_value_rows_progress_under_generation_cleanup_byte_budget() {
    let mut module = AcpModule::new();
    let policy = setup(&mut module, 7);
    let records: Vec<_> = module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(&policy))
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    for (key, mut value) in records {
        value.resize(1 << 20, b' ');
        module.store.put(&key, value);
    }
    remove(&mut module, &policy);
    for height in 1..12 {
        let before = rows(&module, &policy);
        module.end_blocker(&block(height)).unwrap();
        let removed = before - rows(&module, &policy);
        if before > 0 {
            assert!(removed > 0);
        }
        assert!(removed * (1 << 20) < MAX_BYTES);
        module = restore(&module);
        if module
            .store
            .prefix_iter(edits::QUEUE_PREFIX)
            .next()
            .is_none()
        {
            break;
        }
    }
    assert_eq!(rows(&module, &policy), 0);
    assert!(
        module
            .store
            .prefix_iter(edits::QUEUE_PREFIX)
            .next()
            .is_none()
    );
}

#[test]
fn malformed_later_pair_rolls_back_earlier_generation_cleanup() {
    let mut module = AcpModule::new();
    let first = setup(&mut module, 1);
    let second = setup(&mut module, 1);
    remove(&mut module, &first);
    remove(&mut module, &second);
    let key = module
        .store
        .prefix_iter(&relationship_index::incoming_policy_prefix(&second))
        .next()
        .unwrap()
        .0
        .to_vec();
    module.store.put(&key, 9u64.to_be_bytes().to_vec());
    let before = module.store.serialize();
    assert!(module.validate_restored_state().is_err());
    assert!(module.end_blocker(&block(1)).is_err());
    assert_eq!(module.store.serialize(), before);
    assert_eq!(rows(&module, &first), 1);
}

#[test]
fn restoration_rejects_generation_index_and_descriptor_corruption() {
    let mut module = AcpModule::new();
    let policy = setup(&mut module, 2);
    let pair = module
        .query_policy(&policy)
        .unwrap()
        .relations
        .pair(&Relationship::new(
            "file",
            "item-0",
            "reader",
            Subject::entity_set("group", "staff", "member"),
        ))
        .unwrap();
    for key in [
        relationship_index::outgoing_key(&policy, pair),
        relationship_index::incoming_key(&policy, pair),
        relationship_index::active_key(&policy, pair.target),
    ] {
        for bad in [None, Some(vec![0])] {
            let mut candidate = module.clone();
            match bad {
                None => candidate.store.delete(&key),
                Some(value) => candidate.store.put(&key, value),
            }
            assert!(candidate.validate_restored_state().is_err());
        }
    }
    remove(&mut module, &policy);
    module.validate_restored_state().unwrap();
    let marker_key = edits::retired_relation_key(&policy, pair.target);
    let descriptor = edits::load_retired_relation(&module.store, &policy, pair.target)
        .unwrap()
        .unwrap();
    for case in 0..7 {
        let mut candidate = module.clone();
        match case {
            0 => candidate.store.delete(&marker_key),
            1 => candidate
                .store
                .delete(&edits::queue_key(descriptor.sequence)),
            2 => candidate.store.put(
                edits::COUNTER_KEY,
                (descriptor.sequence - 1).to_be_bytes().to_vec(),
            ),
            3 => {
                let mut bad = descriptor.clone();
                bad.relation = "viewer".into();
                candidate
                    .store
                    .put(&marker_key, serde_json::to_vec(&bad).unwrap());
            }
            4 => candidate.store.put(
                &relationship_index::active_key(&policy, pair.target),
                b"[0]".to_vec(),
            ),
            5 => candidate.store.put(
                &[
                    relationship_index::policy_prefix(&policy),
                    b"unknown".to_vec(),
                ]
                .concat(),
                vec![],
            ),
            6 => {
                let key = candidate
                    .store
                    .prefix_iter(&keys::relationship_policy_prefix(&policy))
                    .next()
                    .unwrap()
                    .0
                    .to_vec();
                let mut row: RelationshipRecord =
                    serde_json::from_slice(candidate.store.get_ref(&key).unwrap()).unwrap();
                row.generations.subject = 0;
                candidate.store.put(&key, serde_json::to_vec(&row).unwrap());
            }
            _ => unreachable!(),
        }
        let before = candidate.store.serialize();
        assert!(candidate.validate_restored_state().is_err(), "case {case}");
        assert_eq!(candidate.store.serialize(), before);
    }
}

#[test]
fn padded_internal_jobs_and_impossible_job_budgets_are_rejected() {
    let mut module = AcpModule::new();
    let policy = setup(&mut module, 1);
    remove(&mut module, &policy);
    let marker_key = module
        .store
        .prefix_iter(&edits::retired_relation_prefix(&policy))
        .next()
        .unwrap()
        .0
        .to_vec();
    let descriptor: RetiredRelation =
        serde_json::from_slice(module.store.get_ref(&marker_key).unwrap()).unwrap();
    for key in [marker_key, edits::queue_key(descriptor.sequence)] {
        let mut candidate = module.clone();
        let mut bytes = candidate.store.get(&key).unwrap();
        bytes.push(b' ');
        candidate.store.put(&key, bytes);
        let before = candidate.store.serialize();
        assert!(candidate.validate_restored_state().is_err());
        assert!(candidate.end_blocker(&block(1)).is_err());
        assert_eq!(candidate.store.serialize(), before);
    }
    assert!(Budget::new().start_job(MAX_BYTES + 1, 1).is_err());
}
