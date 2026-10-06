use super::*;
use crate::acp::{AcpModule, PolicyMarshalingType, relationship_mutations};
use crate::kv_store::{InMemoryKvStore, ModuleKvStore, NATIVE_MAX_KEY_BYTES};
use acp::Relationship;
use identity::Did;

fn fixture() -> (InMemoryKvStore, String, RelationshipRecord) {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let policy = module
        .create_policy(
            &owner,
            "name: objects\nresources:\n  - name: file\n    relations:\n      - name: reader\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    let relationship = Relationship::with_entity("file", "report/child", "reader", owner);
    let record = RelationshipRecord {
        incarnation: 0,
        generations: policy.relations.pair(&relationship).unwrap(),
        policy_id: policy.policy.id.clone(),
        relationship,
        archived: false,
        supplied_metadata: Default::default(),
        metadata: policy.metadata,
    };
    (module.store.clone(), policy.policy.id, record)
}

fn primary(record: &RelationshipRecord) -> Vec<u8> {
    keys::relationship_generation_key(
        &record.policy_id,
        record.generations,
        &keys::relationship_storage_key(&record.relationship, record.incarnation),
    )
}

fn count(store: &InMemoryKvStore, record: &RelationshipRecord) -> Option<u64> {
    store
        .get_ref(&key(record))
        .map(|bytes| relationship_index::decode_count(bytes).unwrap())
}

#[test]
fn object_keys_preserve_boundaries_pairs_and_maximum_primary_keys() {
    let (_, policy, mut record) = fixture();
    record.relationship.object_id = "report/雪".into();
    record.generations = RelationPair {
        target: u64::MAX,
        subject: 10,
    };
    let object = incarnation_prefix(&policy, "file", "report/雪", 0);
    assert_eq!(
        parse_pair(&object, &key(&record)).unwrap(),
        record.generations
    );
    assert_eq!(
        key_from_relationship(&policy, record.generations, &primary(&record)).unwrap(),
        key(&record)
    );
    assert!(!key(&record).starts_with(&prefix(&policy, "file", "report")));
    assert_ne!(prefix(&policy, "a/b", "c"), prefix(&policy, "a", "b/c"));

    record.relationship.object_id.clear();
    let overhead = primary(&record).len();
    record.relationship.object_id = "x".repeat((NATIVE_MAX_KEY_BYTES - overhead) / 2);
    let primary = primary(&record);
    assert!(primary.len() <= NATIVE_MAX_KEY_BYTES);
    assert!(NATIVE_MAX_KEY_BYTES - primary.len() <= 1);
    assert!(key(&record).len() < primary.len());
    assert_eq!(
        key_from_relationship(&policy, record.generations, &primary).unwrap(),
        key(&record)
    );
    let mut excessive = primary;
    excessive.resize(NATIVE_MAX_KEY_BYTES + 1, b'0');
    assert!(key_from_relationship(&policy, record.generations, &excessive).is_err());
}

#[test]
fn object_key_parsers_reject_noncanonical_boundaries_and_suffixes() {
    let (_, policy, record) = fixture();
    let object = incarnation_prefix(&policy, "file", "report/child", 0);
    for suffix in [
        "0000000000000001/000000000000000A",
        "0000000000000001/0000000000000000/",
        "000000000000001/0000000000000000",
        "0000000000000001:0000000000000000",
    ] {
        let mut malformed = object.clone();
        malformed.extend_from_slice(suffix.as_bytes());
        assert!(parse_pair(&object, &malformed).is_err());
    }
    assert!(parse_pair(&prefix(&policy, "file", "other"), &key(&record)).is_err());
    let base = keys::relationship_generation_prefix(&policy, record.generations, "");
    let digest = "a".repeat(64);
    for suffix in [
        format!("v1/66696c65/61/0000000000000000/726561646572/{digest}"),
        format!("v3/66696C65/61/0000000000000000/726561646572/{digest}"),
        format!("v3/66696c65/6/0000000000000000/726561646572/{digest}"),
        format!("v3/66696c65/ff/0000000000000000/726561646572/{digest}"),
        format!("v3/66696c65/61/0000000000000000/726561646572/{digest}/extra"),
        format!("v3/66696c65/61/{digest}"),
        format!(
            "v3/66696c65/61/0000000000000000/726561646572/{}",
            "A".repeat(64)
        ),
        format!(
            "v3/66696c65/61/0000000000000000/726561646572/{}",
            "a".repeat(63)
        ),
    ] {
        let mut malformed = base.clone();
        malformed.extend_from_slice(suffix.as_bytes());
        assert!(
            key_from_relationship(&policy, record.generations, &malformed).is_err(),
            "accepted {suffix}"
        );
    }
    assert!(
        key_from_relationship("another-policy", record.generations, &primary(&record)).is_err()
    );
    assert!(
        key_from_relationship(
            &policy,
            RelationPair {
                target: 0,
                subject: 0
            },
            &primary(&record)
        )
        .is_err()
    );
}

#[test]
fn rewrites_and_grouped_removals_preserve_exact_object_counts() {
    let (mut store, _, mut first) = fixture();
    let mut second = first.clone();
    second.relationship.subject = acp::Subject::Entity(Did::new("did:key:second").unwrap());
    let mut third = first.clone();
    third.relationship.object_id = "other".into();
    for record in [&first, &second, &third] {
        relationship_mutations::put(&mut store, record).unwrap();
    }
    assert_eq!(count(&store, &first), Some(2));
    assert_eq!(count(&store, &third), Some(1));
    first.archived = true;
    first.metadata.tx_hash = vec![7; 32];
    relationship_mutations::put(&mut store, &first).unwrap();
    assert_eq!(count(&store, &first), Some(2));
    let before = store.serialize();
    let changes = relationship_mutations::prepare_removals(
        &store,
        &[primary(&first), primary(&second), primary(&third)],
    )
    .unwrap();
    assert_eq!(store.serialize(), before);
    for record in [&first, &third] {
        assert_eq!(
            changes
                .iter()
                .filter(|(changed, _)| *changed == key(record))
                .count(),
            1
        );
    }
    store.apply_records(changes).unwrap();
    assert_eq!(count(&store, &first), None);
    assert_eq!(count(&store, &third), None);
    assert!(
        store
            .prefix_scan(&relationship_index::policy_prefix(&first.policy_id))
            .is_empty()
    );
}

#[test]
fn corrupt_object_counts_fail_before_rewrites_or_bulk_mutation() {
    for corruption in 0..4 {
        let (mut store, _, first) = fixture();
        let mut second = first.clone();
        second.relationship.subject = acp::Subject::Entity(Did::new("did:key:second").unwrap());
        relationship_mutations::put(&mut store, &first).unwrap();
        relationship_mutations::put(&mut store, &second).unwrap();
        match corruption {
            0 => store.delete(&key(&first)),
            1 => store.put(&key(&first), vec![1]),
            2 => store.put(&key(&first), 0u64.to_be_bytes().to_vec()),
            3 => store.put(&key(&first), 1u64.to_be_bytes().to_vec()),
            _ => unreachable!(),
        }
        let before = store.serialize();
        if corruption != 3 {
            assert!(relationship_mutations::put(&mut store, &first).is_err());
            assert_eq!(store.serialize(), before);
        }
        assert!(
            relationship_mutations::prepare_removals(&store, &[primary(&first), primary(&second)])
                .is_err()
        );
        assert_eq!(store.serialize(), before);
    }
}

#[test]
fn overflow_and_late_object_count_corruption_leave_all_records_unchanged() {
    let (mut store, _, first) = fixture();
    relationship_mutations::put(&mut store, &first).unwrap();
    store.put(&key(&first), u64::MAX.to_be_bytes().to_vec());
    let before = store.serialize();
    let mut second = first.clone();
    second.relationship.subject = acp::Subject::Entity(Did::new("did:key:second").unwrap());
    assert!(relationship_mutations::put(&mut store, &second).is_err());
    assert_eq!(store.serialize(), before);

    store.put(&key(&first), 1u64.to_be_bytes().to_vec());
    second.relationship.object_id = "zz-last".into();
    relationship_mutations::put(&mut store, &second).unwrap();
    store.delete(&key(&second));
    let before = store.serialize();
    assert!(
        relationship_mutations::prepare_removals(&store, &[primary(&first), primary(&second)])
            .is_err()
    );
    assert_eq!(store.serialize(), before);
}
