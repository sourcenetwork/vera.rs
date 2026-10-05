use crate::acp::*;

const ORIGINAL: &str = "name: object_restore\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n    relations:\n      - name: member\n";
const WITHOUT_MEMBER: &str = "name: object_restore\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n";

fn owner() -> Did {
    Did::new("did:key:owner").unwrap()
}

fn fixture() -> (AcpModule, String, RelationshipRecord) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&owner(), ORIGINAL, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    for (resource, id) in [("file", "report"), ("group", "staff")] {
        module
            .direct_policy_cmd(
                &owner(),
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: resource.into(),
                    id: id.into(),
                }),
            )
            .unwrap();
    }
    let relationship = Relationship::new(
        "file",
        "report",
        "reader",
        acp::Subject::entity_set("group", "staff", "member"),
    );
    let PolicyCmdResult::SetRelationship { record, .. } = module
        .direct_policy_cmd(&owner(), &policy, PolicyCmd::SetRelationship(relationship))
        .unwrap()
    else {
        panic!("expected relationship");
    };
    (module, policy, record)
}

fn restored(module: &AcpModule) -> AcpModule {
    AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap())
}

#[test]
fn restoration_requires_complete_object_counts_for_live_and_retired_rows() {
    for state in 0..3 {
        let (mut module, policy, record) = fixture();
        if state >= 1 {
            assert_eq!(
                module
                    .edit_policy(
                        &owner(),
                        &policy,
                        WITHOUT_MEMBER,
                        PolicyMarshalingType::ShortYaml
                    )
                    .unwrap()
                    .0,
                1
            );
        }
        if state == 2 {
            module.delete_policy(&owner(), &policy).unwrap();
        }
        restored(&module).validate_restored_state().unwrap();
        for corruption in 0..6 {
            let mut broken = module.clone();
            let key = object_pairs::key(&record);
            match corruption {
                0 => broken.store.delete(&key),
                1 => broken.store.put(&key, vec![1]),
                2 => broken.store.put(&key, 0u64.to_be_bytes().to_vec()),
                3 => broken.store.put(&key, 2u64.to_be_bytes().to_vec()),
                4 => {
                    let mut extra = record.clone();
                    extra.relationship.object_id = "orphan".into();
                    broken
                        .store
                        .put(&object_pairs::key(&extra), 1u64.to_be_bytes().to_vec());
                }
                5 => {
                    let mut malformed = key;
                    malformed.push(b'/');
                    broken.store.put(&malformed, 1u64.to_be_bytes().to_vec());
                }
                _ => unreachable!(),
            }
            assert!(
                restored(&broken).validate_restored_state().is_err(),
                "accepted state {state} corruption {corruption}"
            );
        }
    }
}

#[test]
fn recreated_userset_keeps_separate_physical_object_counts() {
    let (mut module, policy, old) = fixture();
    module
        .edit_policy(
            &owner(),
            &policy,
            WITHOUT_MEMBER,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    module
        .edit_policy(&owner(), &policy, ORIGINAL, PolicyMarshalingType::ShortYaml)
        .unwrap();
    let PolicyCmdResult::SetRelationship {
        record: new,
        record_existed,
    } = module
        .direct_policy_cmd(
            &owner(),
            &policy,
            PolicyCmd::SetRelationship(old.relationship.clone()),
        )
        .unwrap()
    else {
        panic!("expected relationship");
    };
    assert!(!record_existed);
    assert_ne!(old.generations.subject, new.generations.subject);
    assert_ne!(object_pairs::key(&old), object_pairs::key(&new));
    for record in [&old, &new] {
        assert_eq!(
            module.store.get_ref(&object_pairs::key(record)),
            Some(1u64.to_be_bytes().as_slice())
        );
    }
    restored(&module).validate_restored_state().unwrap();
    assert_eq!(
        module
            .query_filter_relationships(&policy, &Default::default())
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn archived_owner_count_survives_unarchive_and_registration_rejection() {
    let (mut module, policy, grant) = fixture();
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let result = module
        .direct_policy_cmd(&owner(), &policy, PolicyCmd::ArchiveObject(object.clone()))
        .unwrap();
    assert!(matches!(
        result,
        PolicyCmdResult::ArchiveObject {
            relationships_removed: 2,
            ..
        }
    ));
    assert!(module.store.has(&object_pairs::key(&grant)));
    let archived = module
        .registration_owner_record(&policy, &object)
        .unwrap()
        .unwrap();
    assert!(archived.archived);
    assert_eq!(
        module.store.get_ref(&object_pairs::key(&archived)),
        Some(1u64.to_be_bytes().as_slice())
    );
    let mut module = restored(&module);
    module.validate_restored_state().unwrap();
    assert!(!module.query_object_owner(&policy, &object).unwrap().0);
    assert!(
        module
            .direct_policy_cmd(&owner(), &policy, PolicyCmd::RegisterObject(object.clone()))
            .is_err()
    );
    module
        .direct_policy_cmd(
            &owner(),
            &policy,
            PolicyCmd::UnarchiveObject(object.clone()),
        )
        .unwrap();
    assert!(module.query_object_owner(&policy, &object).unwrap().0);
    assert_eq!(
        module.store.get_ref(&object_pairs::key(&archived)),
        Some(1u64.to_be_bytes().as_slice())
    );
    assert!(module.store.has(&object_pairs::key(&grant)));
    restored(&module).validate_restored_state().unwrap();
}

#[test]
fn retired_policy_partial_cleanup_restores_exact_remaining_object_counts() {
    let (mut module, policy, _) = fixture();
    for index in 0..130 {
        module
            .direct_policy_cmd(
                &owner(),
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: format!("extra-{index:03}"),
                }),
            )
            .unwrap();
    }
    module.delete_policy(&owner(), &policy).unwrap();
    let before = module
        .store
        .prefix_scan(&keys::relationship_policy_prefix(&policy))
        .len();
    module
        .end_blocker(&BlockExecCtx {
            timestamp: Timestamp {
                block_height: 1,
                seconds: 10,
            },
            ..Default::default()
        })
        .unwrap();
    let after = module
        .store
        .prefix_scan(&keys::relationship_policy_prefix(&policy))
        .len();
    assert!(after > 0 && after < before);
    assert!(module.policy_cleanup_pending(&policy).unwrap());
    let mut module = restored(&module);
    module.validate_restored_state().unwrap();
    module
        .end_blocker(&BlockExecCtx {
            timestamp: Timestamp {
                block_height: 2,
                seconds: 11,
            },
            ..Default::default()
        })
        .unwrap();
    assert!(!module.policy_cleanup_pending(&policy).unwrap());
    assert!(
        module
            .store
            .prefix_scan(&relationship_index::policy_prefix(&policy))
            .is_empty()
    );
    restored(&module).validate_restored_state().unwrap();
}
