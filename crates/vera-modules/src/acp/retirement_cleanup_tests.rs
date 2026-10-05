use super::*;
use record_store::RecordStore;

const POLICY: &str = "name: cleanup\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n    relations:\n      - name: member\n";
const WITHOUT_MEMBER: &str = "name: cleanup\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n";

fn actor() -> Did {
    Did::new("did:key:creator").unwrap()
}

fn setup(count: usize) -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&actor(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    for index in 0..count {
        put(
            &mut module,
            &policy,
            Relationship::with_entity("file", format!("item-{index:03}"), "owner", actor()),
        );
    }
    (module, policy)
}

fn put(module: &mut AcpModule, policy: &str, relationship: Relationship) -> Vec<u8> {
    let definition = module.query_policy(policy).unwrap();
    let record = RelationshipRecord {
        generations: definition.relations.pair(&relationship).unwrap(),
        relationship,
        policy_id: policy.into(),
        archived: false,
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

fn first_key(module: &AcpModule, policy: &str) -> Vec<u8> {
    module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(policy))
        .next()
        .unwrap()
        .0
        .to_vec()
}

#[test]
fn relationship_quantum_combines_pair_writes_and_charges_every_item() {
    let (mut module, policy) = setup(JOB_ITEMS + 1);
    module.delete_policy(&actor(), &policy).unwrap();
    let first = first_key(&module, &policy);
    let before = module.store.serialize();
    let mut budget = Budget::new();
    let (items, changes) = module
        .prepare_cleanup_relationships(&policy, None, &first, usize::MAX, &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!(items, JOB_ITEMS);
    assert_eq!(changes.len(), 2 * JOB_ITEMS + 2);
    assert_eq!(budget.items, MAX_ITEMS - JOB_ITEMS);
    assert_eq!(budget.writes, MAX_WRITES - 2 * JOB_ITEMS - 2);
    assert_eq!(
        module.store.serialize(),
        before,
        "preparation must not mutate"
    );
    RecordStore::apply_records(&mut module.store, changes).unwrap();
    assert_eq!(
        relationship_index::read_pair_count(
            &module.store,
            &policy,
            RelationPair {
                target: 0,
                subject: 0
            },
        )
        .unwrap(),
        1
    );
    module.validate_restored_state().unwrap();
}

#[test]
fn relationship_batches_fit_remaining_item_write_and_byte_budgets() {
    let (mut module, policy) = setup(7);
    let records: Vec<_> = module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(&policy))
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    for (key, mut value) in records {
        value.resize(NATIVE_MAX_VALUE_BYTES, b' ');
        module.store.put(&key, value);
    }
    module.delete_policy(&actor(), &policy).unwrap();
    let first = first_key(&module, &policy);
    let before = module.store.serialize();
    for (items, bytes, writes, expected) in [
        (2, MAX_BYTES, MAX_WRITES, 2),
        (MAX_ITEMS, MAX_BYTES, 3, 0),
        (MAX_ITEMS, MAX_BYTES, 4, 1),
        (MAX_ITEMS, MAX_BYTES, 6, 2),
        (MAX_ITEMS, 2 * NATIVE_MAX_VALUE_BYTES + 8192, MAX_WRITES, 2),
        (MAX_ITEMS, MAX_BYTES, MAX_WRITES, 3),
        (MAX_ITEMS, NATIVE_MAX_VALUE_BYTES, MAX_WRITES, 0),
    ] {
        let mut budget = Budget::new();
        budget.items = items;
        budget.bytes = bytes;
        budget.writes = writes;
        let prepared = module
            .prepare_cleanup_relationships(&policy, None, &first, JOB_ITEMS, &mut budget)
            .unwrap();
        assert_eq!(prepared.as_ref().map_or(0, |(count, _)| *count), expected);
        assert_eq!(budget.items, items - expected);
        assert_eq!(module.store.serialize(), before);
    }
}

#[test]
fn relationship_batches_stop_at_pair_boundaries() {
    let (mut module, policy) = setup(2);
    let reader = put(
        &mut module,
        &policy,
        Relationship::with_entity("file", "other", "reader", actor()),
    );
    module.delete_policy(&actor(), &policy).unwrap();
    let first = first_key(&module, &policy);
    let (items, changes) = module
        .prepare_cleanup_relationships(&policy, None, &first, JOB_ITEMS, &mut Budget::new())
        .unwrap()
        .unwrap();
    assert_eq!(items, 2);
    assert_eq!(changes.len(), 6);
    assert!(changes.iter().all(|(key, _)| key != &reader));
    RecordStore::apply_records(&mut module.store, changes).unwrap();
    assert_eq!(first_key(&module, &policy), reader);
    module.validate_restored_state().unwrap();
}

#[test]
fn malformed_later_row_rolls_back_prior_relationship_batches() {
    let (mut module, policy) = setup(JOB_ITEMS + 1);
    module.delete_policy(&actor(), &policy).unwrap();
    let last = module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(&policy))
        .last()
        .unwrap()
        .0
        .to_vec();
    let original = module.store.get(&last).unwrap();
    for corruption in 0..3 {
        let mut candidate = module.clone();
        let mut row: RelationshipRecord = serde_json::from_slice(&original).unwrap();
        match corruption {
            0 => row.relationship.object_id = "other".into(),
            1 => row.generations.subject = 1,
            2 => row.policy_id = "0".repeat(64),
            _ => unreachable!(),
        }
        candidate
            .store
            .put(&last, serde_json::to_vec(&row).unwrap());
        let before = candidate.store.serialize();
        assert!(candidate.end_blocker(&BlockExecCtx::default()).is_err());
        assert_eq!(candidate.store.serialize(), before);
    }
}

#[test]
fn incoming_userset_cleanup_combines_the_pair_without_touching_new_generations() {
    let (mut module, policy) = setup(0);
    let mut first = None;
    for index in 0..JOB_ITEMS + 1 {
        let key = put(
            &mut module,
            &policy,
            Relationship::new(
                "file",
                format!("item-{index:03}"),
                "reader",
                acp::Subject::entity_set("group", "staff", "member"),
            ),
        );
        first.get_or_insert(key);
    }
    let first = first.unwrap();
    let pair = cleanup_pair(&policy, &first).unwrap();
    module
        .edit_policy(
            &actor(),
            &policy,
            WITHOUT_MEMBER,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    module
        .edit_policy(&actor(), &policy, POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap();
    let fresh = put(
        &mut module,
        &policy,
        Relationship::new(
            "file",
            "item-000",
            "reader",
            acp::Subject::entity_set("group", "staff", "member"),
        ),
    );
    assert_ne!(fresh, first);
    let mut budget = Budget::new();
    let (items, changes) = module
        .prepare_cleanup_relationships(&policy, Some(pair.subject), &first, JOB_ITEMS, &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!(items, JOB_ITEMS);
    assert_eq!(changes.len(), 2 * JOB_ITEMS + 2);
    RecordStore::apply_records(&mut module.store, changes).unwrap();
    assert!(module.store.has(&fresh));
    assert_eq!(
        relationship_index::read_pair_count(&module.store, &policy, pair).unwrap(),
        1
    );
    module.validate_restored_state().unwrap();
}

fn same_object(count: usize) -> (AcpModule, String, Vec<u8>, Vec<u8>) {
    let (mut module, policy) = setup(0);
    for index in 0..count {
        put(
            &mut module,
            &policy,
            Relationship::with_entity(
                "file",
                "shared",
                "reader",
                Did::new(format!("did:key:reader-{index}")).unwrap(),
            ),
        );
    }
    let first = first_key(&module, &policy);
    let pair = cleanup_pair(&policy, &first).unwrap();
    let counter = object_pairs::key_from_relationship(&policy, pair, &first).unwrap();
    module.delete_policy(&actor(), &policy).unwrap();
    (module, policy, first, counter)
}

#[test]
fn same_object_rows_share_one_counter_read_and_write_with_a_tight_write_budget() {
    let (mut module, policy, first, counter) = same_object(JOB_ITEMS + 1);
    let mut budget = Budget::new();
    budget.writes = JOB_ITEMS + 3;
    let (items, changes) = module
        .prepare_cleanup_relationships(&policy, None, &first, JOB_ITEMS, &mut budget)
        .unwrap()
        .unwrap();
    assert_eq!(items, JOB_ITEMS);
    assert_eq!(changes.len(), JOB_ITEMS + 3);
    assert_eq!(changes.iter().filter(|(key, _)| key == &counter).count(), 1);
    assert_eq!(budget.writes, 0);
    RecordStore::apply_records(&mut module.store, changes).unwrap();
    assert_eq!(
        module.store.get_ref(&counter),
        Some(1u64.to_be_bytes().as_slice())
    );
    module.validate_restored_state().unwrap();
}

#[test]
fn maximum_value_batch_charges_object_counter_bytes_before_decoding() {
    let (mut module, policy, first, counter) = same_object(2);
    let mut value = module.store.get(&first).unwrap();
    value.resize(NATIVE_MAX_VALUE_BYTES, b' ');
    module.store.put(&first, value);
    let pair = cleanup_pair(&policy, &first).unwrap();
    let mut required = keys::policy_key(&policy).len()
        + record_size(&first, module.store.get_ref(&first).unwrap()).unwrap()
        + first.len();
    for key in [
        relationship_index::outgoing_key(&policy, pair),
        relationship_index::incoming_key(&policy, pair),
        counter,
    ] {
        required += 2 * record_size(&key, module.store.get_ref(&key).unwrap()).unwrap();
    }
    assert!(required < MAX_BYTES);
    let before = module.store.serialize();
    for bytes in [required - 1, required] {
        let mut budget = Budget::new();
        budget.bytes = bytes;
        let prepared = module
            .prepare_cleanup_relationships(&policy, None, &first, 1, &mut budget)
            .unwrap();
        if bytes == required {
            let (items, changes) = prepared.unwrap();
            assert_eq!(items, 1);
            assert_eq!(changes.len(), 4);
            assert_eq!(budget.bytes, 0);
        } else {
            assert!(prepared.is_none());
        }
        assert_eq!(module.store.serialize(), before);
    }
}

#[test]
fn missing_or_corrupt_object_counters_roll_back_prior_cleanup_batches() {
    let (mut module, policy) = setup(JOB_ITEMS + 1);
    module.delete_policy(&actor(), &policy).unwrap();
    let last = module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(&policy))
        .last()
        .unwrap()
        .0
        .to_vec();
    let counter =
        object_pairs::key_from_relationship(&policy, cleanup_pair(&policy, &last).unwrap(), &last)
            .unwrap();
    for value in [None, Some(vec![1]), Some(0u64.to_be_bytes().to_vec())] {
        let mut candidate = module.clone();
        match value {
            Some(value) => candidate.store.put(&counter, value),
            None => candidate.store.delete(&counter),
        }
        let before = candidate.store.serialize();
        assert!(candidate.end_blocker(&BlockExecCtx::default()).is_err());
        assert_eq!(candidate.store.serialize(), before);
    }
    let (mut module, _, _, counter) = same_object(JOB_ITEMS + 1);
    module.store.put(&counter, 1u64.to_be_bytes().to_vec());
    let before = module.store.serialize();
    assert!(module.end_blocker(&BlockExecCtx::default()).is_err());
    assert_eq!(module.store.serialize(), before);
}
