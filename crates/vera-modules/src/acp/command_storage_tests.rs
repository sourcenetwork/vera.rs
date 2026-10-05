use super::*;
use crate::acp::*;

fn did(name: &str) -> Did {
    Did::new(format!("did:key:{name}")).unwrap()
}
fn object() -> Object {
    Object {
        resource: "file".into(),
        id: "report".into(),
    }
}
fn fixture() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module.create_policy(&did("owner"), "name: storage\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n", PolicyMarshalingType::ShortYaml).unwrap().policy.id;
    module
        .direct_policy_cmd(&did("owner"), &policy, PolicyCmd::RegisterObject(object()))
        .unwrap();
    (module, policy)
}
fn record(module: &AcpModule, policy: &str) -> RelationshipRecord {
    let policy_record = module.query_policy(policy).unwrap();
    let relationship = Relationship::with_entity("file", "report", "reader", did("reader"));
    RelationshipRecord {
        incarnation: 0,
        generations: policy_record.relations.pair(&relationship).unwrap(),
        relationship,
        policy_id: policy.into(),
        archived: false,
        metadata: policy_record.metadata,
        supplied_metadata: Default::default(),
    }
}
fn primary(record: &RelationshipRecord) -> Vec<u8> {
    keys::relationship_generation_key(
        &record.policy_id,
        record.generations,
        &keys::relationship_storage_key(&record.relationship, record.incarnation),
    )
}
fn reads(record: &RelationshipRecord) -> Vec<Vec<u8>> {
    vec![
        keys::policy_key(&record.policy_id),
        primary(record),
        object_state::key(
            &record.policy_id,
            &record.relationship.resource,
            &record.relationship.object_id,
        ),
        relationship_index::outgoing_key(&record.policy_id, record.generations),
        relationship_index::incoming_key(&record.policy_id, record.generations),
        relationship_index::logical_key(&record.policy_id, record.generations),
        relationship_index::active_key(&record.policy_id, record.generations.target),
        object_pairs::key(record),
    ]
}
fn price(store: &InMemoryKvStore, keys: &[Vec<u8>], changes: &[RecordChange]) -> u64 {
    let reads: u64 = keys
        .iter()
        .map(|key| {
            100 + (key.len() as u64 + store.get_ref(key).map_or(0, |v| v.len()) as u64).div_ceil(16)
        })
        .sum();
    let writes: u64 = changes
        .iter()
        .map(|(key, value)| {
            200 + 2 * (key.len() as u64 + value.as_ref().map_or(0, Vec::len) as u64).div_ceil(16)
        })
        .sum();
    reads + writes
}

#[test]
fn central_point_plans_pay_each_primary_counter_and_directory_once() {
    let (original, policy) = fixture();
    let mut record = record(&original, &policy);
    record
        .supplied_metadata
        .attributes
        .insert("note".into(), "x".repeat(60 << 10));
    let mut current = original;
    // New pair, metadata-only rewrite, and last-pair deletion have distinct plans.
    for phase in 0..3 {
        if phase == 1 {
            record.archived = true;
        }
        let mut expected = current.clone();
        if phase == 2 {
            relationship_mutations::remove(&mut expected.store, &primary(&record)).unwrap();
        } else {
            relationship_mutations::put(&mut expected.store, &record).unwrap();
        }
        let changes = expected.store.diff_from(&current.store);
        assert_eq!(changes.len(), if phase == 1 { 1 } else { 6 });
        let cost = price(&current.store, &reads(&record), &changes);
        let mut exact = current.clone();
        let budget = CommandBudget::new(cost);
        if phase == 2 {
            exact
                .remove_relationship_key_with_budget(&primary(&record), &budget)
                .unwrap();
        } else {
            exact
                .set_relationship_with_budget(&record, &budget)
                .unwrap();
        }
        assert_eq!(budget.consumed(), cost);
        assert_eq!(exact.store.serialize(), expected.store.serialize());
        exact.validate_restored_state().unwrap();
        let mut short = current.clone();
        let budget = CommandBudget::new(cost - 1);
        let result = if phase == 2 {
            short.remove_relationship_key_with_budget(&primary(&record), &budget)
        } else {
            short.set_relationship_with_budget(&record, &budget)
        };
        assert!(matches!(result, Err(AcpError::CommandBudgetExceeded)));
        assert!(budget.is_exhausted());
        assert_eq!(short.store.serialize(), current.store.serialize());
        current = exact;
    }
}

#[test]
fn point_storage_preserves_late_corruption_and_predecode_exhaustion() {
    let (mut module, policy) = fixture();
    let record = record(&module, &policy);
    module.set_relationship(&record).unwrap();
    let original = module;
    for (key, bad) in [
        (
            relationship_index::incoming_key(&policy, record.generations),
            Vec::new(),
        ),
        (
            relationship_index::active_key(&policy, record.generations.target),
            b"[]".to_vec(),
        ),
        (object_pairs::key(&record), 0u64.to_be_bytes().to_vec()),
    ] {
        let mut corrupt = original.clone();
        corrupt.store.put(&key, bad);
        let before = corrupt.store.serialize();
        let budget = CommandBudget::new(u64::MAX);
        assert!(matches!(
            corrupt.set_relationship_with_budget(&record, &budget),
            Err(AcpError::State(_))
        ));
        assert!(budget.consumed() > 0);
        assert_eq!(corrupt.store.serialize(), before);
    }
    let mut corrupt = original;
    corrupt.store.put(&primary(&record), vec![b'!'; 1 << 20]);
    let before = corrupt.store.serialize();
    let budget = CommandBudget::new(10_000);
    assert!(matches!(
        corrupt.set_relationship_with_budget(&record, &budget),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert!(matches!(
        corrupt.set_relationship_with_budget(&record, &CommandBudget::new(u64::MAX)),
        Err(AcpError::State(_))
    ));
    assert_eq!(corrupt.store.serialize(), before);
}

#[path = "command_storage_lifecycle_tests.rs"]
mod lifecycle;
