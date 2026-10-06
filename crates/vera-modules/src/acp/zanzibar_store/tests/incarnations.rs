use super::*;

fn retire(store: &QmdbZanzibarStore, relationship: &Relationship) {
    let mut records = store.store.write().unwrap();
    let policy = read_policy(&*records, POLICY).unwrap().unwrap();
    let pair = policy.relations.pair(relationship).unwrap();
    let (_, incarnation) = object_state::prepare_advance(
        &*records,
        POLICY,
        &relationship.resource,
        &relationship.object_id,
    )
    .unwrap();
    let mut changes = relationship_index::prepare_counts(
        &*records,
        POLICY,
        &[(pair, false, 0, 1)],
        Some(&policy.relations),
        true,
    )
    .unwrap();
    changes.push(incarnation);
    records.apply_records(changes).unwrap();
}

#[test]
fn unregistered_objects_select_new_grants_and_preserve_incarnation_on_deletion() {
    let store = adapter();
    let relationship = Relationship::with_entity("document", "role", "reader", did(ALICE));
    block_on(store.store_relationship(POLICY, &relationship)).unwrap();
    let old_key = physical_key(&store.store.read().unwrap(), &relationship);
    retire(&store, &relationship);
    assert!(store.store.read().unwrap().has(&old_key));
    assert!(
        block_on(store.get_relation_subjects(POLICY, "document", "role", "reader"))
            .unwrap()
            .is_empty()
    );
    assert!(
        !block_on(store.has_relationship(
            POLICY,
            "document",
            "role",
            "reader",
            &relationship.subject
        ))
        .unwrap()
    );
    assert!(!block_on(store.delete_relationship(POLICY, &relationship)).unwrap());
    block_on(store.store_relationship(POLICY, &relationship)).unwrap();
    let fresh_key = physical_key(&store.store.read().unwrap(), &relationship);
    assert_ne!(old_key, fresh_key);
    assert_eq!(
        block_on(store.get_relation_subjects(POLICY, "document", "role", "reader")).unwrap(),
        vec![relationship.subject.clone()]
    );
    assert!(block_on(store.delete_relationship(POLICY, &relationship)).unwrap());
    assert!(store.store.read().unwrap().has(&old_key));
    assert!(!store.store.read().unwrap().has(&fresh_key));
    block_on(store.store_relationship(POLICY, &relationship)).unwrap();
    block_on(store.delete_object_relationships(POLICY, "document", "role")).unwrap();
    let records = store.store.read().unwrap();
    assert!(!records.has(&old_key));
    assert!(!records.has(&fresh_key));
    assert_eq!(
        object_state::read(&*records, POLICY, "document", "role").unwrap(),
        1
    );
    drop(records);
    block_on(store.store_relationship(POLICY, &relationship)).unwrap();
    assert_eq!(
        physical_key(&store.store.read().unwrap(), &relationship),
        fresh_key
    );
}

#[test]
fn generic_policy_deletion_removes_validated_object_points_atomically() {
    let store = adapter();
    let relationship = Relationship::with_entity("document", "role", "reader", did(ALICE));
    block_on(store.store_relationship(POLICY, &relationship)).unwrap();
    retire(&store, &relationship);
    let key = object_state::key(POLICY, "document", "role");
    store.store.write().unwrap().put(&key, vec![0]);
    let before = store.store.read().unwrap().serialize();
    assert!(block_on(store.delete_policy(POLICY)).is_err());
    assert_eq!(store.store.read().unwrap().serialize(), before);
    store
        .store
        .write()
        .unwrap()
        .put(&key, 1_u64.to_be_bytes().to_vec());
    assert!(block_on(store.delete_policy(POLICY)).unwrap());
    let records = store.store.read().unwrap();
    assert!(
        records
            .prefix_scan(&object_state::policy_prefix(POLICY))
            .is_empty()
    );
    assert!(
        records
            .prefix_scan(&keys::relationship_policy_prefix(POLICY))
            .is_empty()
    );
    assert!(
        records
            .prefix_scan(&relationship_index::policy_prefix(POLICY))
            .is_empty()
    );
}

#[test]
fn adapter_reads_reject_malformed_state_and_policy_deletion_keeps_scheduled_cleanup() {
    let store = adapter();
    let relationship = Relationship::with_entity("document", "role", "reader", did(ALICE));
    block_on(store.store_relationship(POLICY, &relationship)).unwrap();
    let key = object_state::key(POLICY, "document", "role");
    store
        .store
        .write()
        .unwrap()
        .put(&key, 0_u64.to_be_bytes().to_vec());
    assert!(
        block_on(store.has_relationship(
            POLICY,
            "document",
            "role",
            "reader",
            &relationship.subject
        ))
        .is_err()
    );
    assert!(block_on(store.get_relation_subjects(POLICY, "document", "role", "reader")).is_err());
    store.store.write().unwrap().delete(&key);
    let marker = super::super::super::object_cleanup::marker_prefix(POLICY);
    store
        .store
        .write()
        .unwrap()
        .put(&marker, b"pending".to_vec());
    let before = store.store.read().unwrap().serialize();
    assert!(
        block_on(store.delete_policy(POLICY))
            .unwrap_err()
            .to_string()
            .contains("scheduled ACP object retirement")
    );
    assert_eq!(store.store.read().unwrap().serialize(), before);
}
