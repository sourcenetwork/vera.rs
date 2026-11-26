use super::*;

/// Advance the object's incarnation as archiving does, keeping its old rows.
fn retire(store: &mut InMemoryKvStore, relationship: &Relationship) {
    let policy = read_policy(store, POLICY).unwrap().unwrap();
    let pair = policy.relations.pair(relationship).unwrap();
    let (_, incarnation) = object_state::prepare_advance(
        store,
        POLICY,
        relationship.object.resource.as_str(),
        relationship.object.id.as_str(),
    )
    .unwrap();
    let mut changes = relationship_index::prepare_counts(
        store,
        POLICY,
        &[(pair, false, 0, 1)],
        Some(&policy.relations),
        true,
    )
    .unwrap();
    changes.push(incarnation);
    store.apply_records(changes).unwrap();
}

#[test]
fn grants_of_a_retired_incarnation_do_not_count() {
    let mut kv = InMemoryKvStore::default();
    let grant = alice("document", "role", "reader");
    seed(&mut kv, &grant, false);
    let old_key = physical_key(&kv, &grant);
    retire(&mut kv, &grant);
    assert!(kv.has(&old_key));
    assert!(subjects(kv.clone(), "role", "reader").unwrap().is_empty());
    assert!(!has(kv.clone(), &grant).unwrap());
    seed(&mut kv, &grant, false);
    let fresh_key = physical_key(&kv, &grant);
    assert_ne!(old_key, fresh_key);
    assert_eq!(
        subjects(kv.clone(), "role", "reader").unwrap(),
        vec![grant.subject.clone()]
    );
    assert!(grants(kv).is_live(&grant).unwrap());
}

#[test]
fn owner_grants_ignore_incarnations() {
    let mut kv = InMemoryKvStore::default();
    let owner = alice("document", "role", "owner");
    let reader = alice("document", "role", "reader");
    seed(&mut kv, &owner, false);
    seed(&mut kv, &reader, false);
    retire(&mut kv, &reader);
    assert!(has(kv.clone(), &owner).unwrap());
    assert_eq!(
        subjects(kv, "role", "owner").unwrap(),
        vec![owner.subject.clone()]
    );
}

#[test]
fn malformed_object_state_is_an_error() {
    let mut kv = InMemoryKvStore::default();
    let grant = alice("document", "role", "reader");
    seed(&mut kv, &grant, false);
    kv.put(
        &object_state::key(POLICY, "document", "role"),
        0_u64.to_be_bytes().to_vec(),
    );
    assert!(has(kv.clone(), &grant).is_err());
    assert!(subjects(kv, "role", "reader").is_err());
}
