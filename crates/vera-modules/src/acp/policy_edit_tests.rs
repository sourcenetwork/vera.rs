use super::*;

fn pruning_fixture() -> (AcpModule, Did, String, Relationship) {
    let owner = Did::new("did:key:owner").unwrap();
    let original =
        "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n";
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&owner, original, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    for id in ["before", "report"] {
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: id.into(),
                }),
            )
            .unwrap();
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::SetRelationship(Relationship::with_entity(
                    "file",
                    id,
                    "reader",
                    owner.clone(),
                )),
            )
            .unwrap();
    }
    let relationship = Relationship::with_entity("file", "report", "reader", owner.clone());
    (module, owner, policy, relationship)
}

#[test]
fn editing_rejects_corrupt_pair_indexes_without_partial_invalidation() {
    let replacement = "name: files\nresources:\n  - name: file\n";
    for corruption in 0..6 {
        let (mut module, owner, policy, relationship) = pruning_fixture();
        let pair = module
            .query_policy(&policy)
            .unwrap()
            .relations
            .pair(&relationship)
            .unwrap();
        let outgoing = relationship_index::outgoing_key(&policy, pair);
        let incoming = relationship_index::incoming_key(&policy, pair);
        let directory = relationship_index::active_key(&policy, pair.target);
        match corruption {
            0 => module.store.delete(&incoming),
            1 => module.store.put(&incoming, vec![1]),
            2 => module.store.put(&incoming, 3u64.to_be_bytes().to_vec()),
            3 => module.store.put(&outgoing, 0u64.to_be_bytes().to_vec()),
            4 => module.store.put(&directory, b"[0,0]".to_vec()),
            5 => module
                .store
                .put(&directory, b"[18446744073709551615]".to_vec()),
            _ => unreachable!(),
        }
        let before = module.store.serialize();
        assert!(
            module
                .edit_policy(
                    &owner,
                    &policy,
                    replacement,
                    PolicyMarshalingType::ShortYaml
                )
                .is_err(),
            "corruption {corruption} accepted"
        );
        assert_eq!(module.store.serialize(), before);
        assert!(
            module.zanzibar_policies[&policy]
                .get_relation("file", "reader")
                .is_some()
        );
    }
}

#[test]
fn primary_corruption_is_rejected_by_reads_restoration_and_atomic_cleanup() {
    for corruption in 0..3 {
        let (mut module, owner, policy, relationship) = pruning_fixture();
        let pair = module
            .query_policy(&policy)
            .unwrap()
            .relations
            .pair(&relationship)
            .unwrap();
        let key = keys::relationship_generation_key(
            &policy,
            pair,
            &keys::relationship_storage_key(&relationship),
        );
        let mut record: RelationshipRecord =
            serde_json::from_slice(&module.store.get(&key).unwrap()).unwrap();
        let bad = match corruption {
            0 => b"{".to_vec(),
            1 => {
                record.policy_id = "other".into();
                serde_json::to_vec(&record).unwrap()
            }
            _ => {
                record.relationship.object_id = "other".into();
                serde_json::to_vec(&record).unwrap()
            }
        };
        module.store.put(&key, bad);
        assert!(module.validate_restored_state().is_err());
        let selector = RelationshipSelector {
            object_selector: Some(ObjectSelector::Exact(Object {
                resource: "file".into(),
                id: "report".into(),
            })),
            relation_selector: Some(RelationSelector::Exact("reader".into())),
            subject_selector: None,
        };
        assert!(
            module
                .query_filter_relationships(&policy, &selector)
                .is_err()
        );
        // Editing validates its bounded index plan; primary rows are validated by
        // current reads, restoration and physical cleanup rather than a global edit scan.
        assert_eq!(
            module
                .edit_policy(
                    &owner,
                    &policy,
                    "name: files\nresources:\n  - name: file\n",
                    PolicyMarshalingType::ShortYaml
                )
                .unwrap()
                .0,
            2
        );
        let before = module.store.serialize();
        assert!(
            module
                .end_blocker(&BlockExecCtx {
                    timestamp: Timestamp {
                        block_height: 1,
                        seconds: 10
                    },
                    ..Default::default()
                })
                .is_err()
        );
        assert_eq!(module.store.serialize(), before);
        assert!(
            AcpModule::from_store(InMemoryKvStore::deserialize(&before).unwrap())
                .validate_restored_state()
                .is_err()
        );
    }
}

#[test]
fn policy_edits_isolate_forks_and_share_unchanged_definitions() {
    let owner = Did::new("did:key:owner").unwrap();
    let original =
        "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n";
    let replacement =
        "name: files\nresources:\n  - name: file\n    relations:\n      - name: writer\n";
    let mut parent = AcpModule::new();
    let ids: Vec<_> = (0..128)
        .map(|_| {
            parent
                .create_policy(&owner, original, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .policy
                .id
        })
        .collect();
    let before = parent.store.serialize();
    let mut fork = parent.clone();
    let sibling = parent.clone();
    fork.edit_policy(
        &owner,
        &ids[64],
        replacement,
        PolicyMarshalingType::ShortYaml,
    )
    .unwrap();
    for (i, id) in ids.iter().enumerate() {
        assert!(Arc::ptr_eq(
            &parent.zanzibar_policies[id],
            &sibling.zanzibar_policies[id]
        ));
        assert_eq!(
            Arc::ptr_eq(&parent.zanzibar_policies[id], &fork.zanzibar_policies[id]),
            i != 64
        );
        assert!(
            parent.zanzibar_policies[id]
                .get_relation("file", "reader")
                .is_some()
        );
    }
    assert!(
        fork.zanzibar_policies[&ids[64]]
            .get_relation("file", "reader")
            .is_none()
    );
    assert!(
        fork.zanzibar_policies[&ids[64]]
            .get_relation("file", "writer")
            .is_some()
    );
    assert_eq!(parent.store.serialize(), before);
    assert_eq!(sibling.store.serialize(), before);
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&fork.store.serialize()).unwrap());
    assert_eq!(restored.store.serialize(), fork.store.serialize());
    for id in &ids {
        assert_eq!(
            serde_json::to_vec(restored.zanzibar_policies[id].as_ref()).unwrap(),
            serde_json::to_vec(fork.zanzibar_policies[id].as_ref()).unwrap()
        );
    }
}

#[path = "policy_edit_generation_tests.rs"]
mod generations;

#[path = "policy_edit_schema_tests.rs"]
mod schema;
