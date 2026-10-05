use crate::acp::*;

const POLICY: &str = "name: logical\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n    relations:\n      - name: member\n";
const NO_MEMBER: &str = "name: logical\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n";
const NO_RELATIONS: &str = "name: logical\nresources:\n  - name: file\n  - name: group\n";

fn owner() -> Did {
    Did::new("did:key:owner").unwrap()
}

fn fixture(count: usize) -> (AcpModule, String, RelationshipRecord) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let definition = module.query_policy(&policy).unwrap();
    let mut last = None;
    for index in 0..count {
        let relationship = Relationship::new(
            "file",
            format!("item-{index:03}"),
            "reader",
            acp::Subject::entity_set("group", "staff", "member"),
        );
        let record = RelationshipRecord {
            generations: definition.relations.pair(&relationship).unwrap(),
            policy_id: policy.clone(),
            relationship,
            archived: false,
            supplied_metadata: Default::default(),
            metadata: definition.metadata.clone(),
        };
        relationship_mutations::put(&mut module.store, &record).unwrap();
        last = Some(record);
    }
    (module, policy, last.unwrap())
}

fn logical(module: &AcpModule, policy: &str, pair: RelationPair) -> u64 {
    relationship_index::read_logical_count(&module.store, policy, pair).unwrap()
}

fn restore(module: &AcpModule) -> Result<()> {
    AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap())
        .validate_restored_state()
}

#[test]
fn logical_counts_clear_once_for_target_or_subject_retirement_and_never_recount_old_rows() {
    for replacement in [NO_MEMBER, NO_RELATIONS] {
        let (mut module, policy, old) = fixture(3);
        assert_eq!(logical(&module, &policy, old.generations), 3);
        assert_eq!(
            module
                .edit_policy(
                    &owner(),
                    &policy,
                    replacement,
                    PolicyMarshalingType::ShortYaml
                )
                .unwrap()
                .0,
            3
        );
        assert_eq!(logical(&module, &policy, old.generations), 0);
        assert_eq!(
            relationship_index::read_pair_count(&module.store, &policy, old.generations).unwrap(),
            3
        );
        restore(&module).unwrap();
        assert_eq!(
            module
                .edit_policy(&owner(), &policy, POLICY, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .0,
            0
        );
        let mut fresh = old.clone();
        fresh.generations = module
            .query_policy(&policy)
            .unwrap()
            .relations
            .pair(&fresh.relationship)
            .unwrap();
        assert_ne!(fresh.generations, old.generations);
        relationship_mutations::put(&mut module.store, &fresh).unwrap();
        assert_eq!(logical(&module, &policy, fresh.generations), 1);
        module.end_blocker(&BlockExecCtx::default()).unwrap();
        assert_eq!(
            relationship_index::read_pair_count(&module.store, &policy, old.generations).unwrap(),
            0
        );
        assert_eq!(logical(&module, &policy, fresh.generations), 1);
        assert_eq!(
            module
                .edit_policy(
                    &owner(),
                    &policy,
                    NO_RELATIONS,
                    PolicyMarshalingType::ShortYaml
                )
                .unwrap()
                .0,
            1
        );
        restore(&module).unwrap();
    }
}

#[test]
fn corrupt_logical_counts_reject_rewrites_removals_edits_and_restoration_atomically() {
    let (module, policy, row) = fixture(2);
    let key = relationship_index::logical_key(&policy, row.generations);
    let primary = keys::relationship_generation_key(
        &policy,
        row.generations,
        &keys::relationship_storage_key(&row.relationship),
    );
    for bytes in [
        None,
        Some(vec![1]),
        Some(0u64.to_be_bytes().to_vec()),
        Some(1u64.to_be_bytes().to_vec()),
        Some(u64::MAX.to_be_bytes().to_vec()),
    ] {
        let mut broken = module.clone();
        match bytes {
            None => broken.store.delete(&key),
            Some(bytes) => broken.store.put(&key, bytes),
        }
        let before = broken.store.serialize();
        assert!(relationship_mutations::put(&mut broken.store, &row).is_err());
        assert_eq!(broken.store.serialize(), before);
        assert!(relationship_mutations::remove(&mut broken.store, &primary).is_err());
        assert_eq!(broken.store.serialize(), before);
        assert!(
            broken
                .edit_policy(
                    &owner(),
                    &policy,
                    NO_MEMBER,
                    PolicyMarshalingType::ShortYaml
                )
                .is_err()
        );
        assert_eq!(broken.store.serialize(), before);
        assert!(restore(&broken).is_err());
    }
}

#[test]
fn restoration_rejects_retired_or_orphan_logical_counts() {
    let (mut module, policy, row) = fixture(1);
    module
        .edit_policy(
            &owner(),
            &policy,
            NO_MEMBER,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    restore(&module).unwrap();
    for pair in [
        row.generations,
        RelationPair {
            target: u64::MAX,
            subject: 0,
        },
    ] {
        let mut broken = module.clone();
        broken.store.put(
            &relationship_index::logical_key(&policy, pair),
            1u64.to_be_bytes().to_vec(),
        );
        assert!(restore(&broken).is_err());
    }
}

#[test]
fn retired_policy_cleanup_keeps_exact_remaining_logical_counts() {
    let (mut module, policy, row) = fixture(130);
    module.delete_policy(&owner(), &policy).unwrap();
    assert_eq!(logical(&module, &policy, row.generations), 130);
    module.end_blocker(&BlockExecCtx::default()).unwrap();
    let remaining =
        relationship_index::read_pair_count(&module.store, &policy, row.generations).unwrap();
    assert!(remaining > 0 && remaining < 130);
    assert_eq!(logical(&module, &policy, row.generations), remaining);
    restore(&module).unwrap();
    let mut missing = module.clone();
    missing
        .store
        .delete(&relationship_index::logical_key(&policy, row.generations));
    assert!(restore(&missing).is_err());
    module.end_blocker(&BlockExecCtx::default()).unwrap();
    assert!(!module.policy_cleanup_pending(&policy).unwrap());
    assert!(
        module
            .store
            .prefix_iter(&relationship_index::logical_policy_prefix(&policy))
            .next()
            .is_none()
    );
    restore(&module).unwrap();
}

#[test]
fn retired_policy_gc_rejects_missing_mismatched_and_retired_logical_counts_atomically() {
    let (mut module, policy, row) = fixture(130);
    module.delete_policy(&owner(), &policy).unwrap();
    let key = relationship_index::logical_key(&policy, row.generations);
    for value in [
        None,
        Some(1u64.to_be_bytes().to_vec()),
        Some(131u64.to_be_bytes().to_vec()),
    ] {
        let mut broken = module.clone();
        match value {
            None => broken.store.delete(&key),
            Some(value) => broken.store.put(&key, value),
        }
        let before = broken.store.serialize();
        assert!(broken.end_blocker(&BlockExecCtx::default()).is_err());
        assert_eq!(broken.store.serialize(), before);
    }
    let (mut module, policy, row) = fixture(2);
    module
        .edit_policy(
            &owner(),
            &policy,
            NO_MEMBER,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    module.delete_policy(&owner(), &policy).unwrap();
    module.store.put(
        &relationship_index::logical_key(&policy, row.generations),
        2u64.to_be_bytes().to_vec(),
    );
    let before = module.store.serialize();
    assert!(module.end_blocker(&BlockExecCtx::default()).is_err());
    assert_eq!(module.store.serialize(), before);
}
