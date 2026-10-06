use super::*;
use crate::acp::types::Operation;

const READER: &str = "did:key:reader";

fn definition(reader: bool, member: bool) -> String {
    format!(
        "name: generations\nresources:\n  - name: file\n    relations:\n{}      - name: writer\n    permissions:\n      - name: read\n        expr: {}\n  - name: group\n{}",
        if reader { "      - name: reader\n" } else { "" },
        if reader { "reader" } else { "owner" },
        if member {
            "    relations:\n      - name: member\n"
        } else {
            ""
        },
    )
}

fn fixture() -> (AcpModule, Did, String) {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let policy = module
        .create_policy(
            &owner,
            &definition(true, true),
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    for (resource, id) in [("file", "report"), ("group", "staff")] {
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: resource.into(),
                    id: id.into(),
                }),
            )
            .unwrap();
    }
    (module, owner, policy)
}

fn grant(
    module: &mut AcpModule,
    owner: &Did,
    policy: &str,
    relationship: Relationship,
) -> RelationshipRecord {
    let PolicyCmdResult::SetRelationship {
        record_existed,
        record,
    } = module
        .direct_policy_cmd(owner, policy, PolicyCmd::SetRelationship(relationship))
        .unwrap()
    else {
        panic!("expected relationship")
    };
    assert!(!record_existed);
    record
}

fn edge(relation: &str) -> Relationship {
    Relationship::new(
        "file",
        "report",
        relation,
        acp::Subject::entity_set("group", "staff", "member"),
    )
}

fn member() -> Relationship {
    Relationship::with_entity("group", "staff", "member", Did::new(READER).unwrap())
}

fn can_read(module: &AcpModule, policy: &str, object: &str) -> bool {
    module
        .query_verify_access_request(
            policy,
            &AccessRequest {
                actor: Actor(Did::new(READER).unwrap()),
                operations: vec![Operation {
                    object: Object {
                        resource: "file".into(),
                        id: object.into(),
                    },
                    permission: "read".into(),
                }],
            },
        )
        .unwrap()
}

fn restore(module: &AcpModule) -> AcpModule {
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    restored.validate_restored_state().unwrap();
    restored
}

fn reader_selector() -> RelationshipSelector {
    RelationshipSelector {
        object_selector: Some(ObjectSelector::ResourcePredicate("file".into())),
        relation_selector: Some(RelationSelector::Exact("reader".into())),
        subject_selector: None,
    }
}

#[test]
fn recreating_target_or_userset_relation_never_resurrects_retained_grants() {
    for remove_subject in [false, true] {
        let (mut module, owner, policy) = fixture();
        grant(&mut module, &owner, &policy, member());
        let previous = grant(&mut module, &owner, &policy, edge("reader"));
        assert!(can_read(&module, &policy, "report"));
        let retained_key = keys::relationship_generation_key(
            &policy,
            previous.generations,
            &keys::relationship_storage_key(&previous.relationship, previous.incarnation),
        );
        let (removed, _) = module
            .edit_policy(
                &owner,
                &policy,
                &definition(remove_subject, !remove_subject),
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        assert_eq!(removed, if remove_subject { 2 } else { 1 });
        assert!(module.store.has(&retained_key));
        assert!(!can_read(&module, &policy, "report"));
        module = restore(&module);
        assert_eq!(
            module
                .edit_policy(
                    &owner,
                    &policy,
                    &definition(true, true),
                    PolicyMarshalingType::ShortYaml
                )
                .unwrap()
                .0,
            0
        );
        module = restore(&module);
        if remove_subject {
            grant(&mut module, &owner, &policy, member());
        }
        assert!(!can_read(&module, &policy, "report"));
        assert!(
            module
                .query_filter_relationships(&policy, &reader_selector())
                .unwrap()
                .is_empty()
        );
        let current = grant(&mut module, &owner, &policy, edge("reader"));
        assert_ne!(current.generations, previous.generations);
        assert!(can_read(&restore(&module), &policy, "report"));
        assert!(module.store.has(&retained_key));
    }
}

#[test]
fn edit_counts_archived_rows_and_double_invalid_pairs_exactly_once() {
    let (mut module, owner, policy) = fixture();
    grant(&mut module, &owner, &policy, member());
    let mut archived = grant(&mut module, &owner, &policy, edge("reader"));
    archived.archived = true;
    module.set_relationship(&archived).unwrap();
    grant(&mut module, &owner, &policy, edge("writer"));
    grant(
        &mut module,
        &owner,
        &policy,
        Relationship::with_entity("file", "report", "reader", Did::new(READER).unwrap()),
    );
    module.validate_restored_state().unwrap();
    let before = module
        .store
        .prefix_scan(&keys::relationship_policy_prefix(&policy));
    assert_eq!(
        module
            .edit_policy(
                &owner,
                &policy,
                &definition(false, false),
                PolicyMarshalingType::ShortYaml
            )
            .unwrap()
            .0,
        4
    );
    assert_eq!(
        module
            .store
            .prefix_scan(&keys::relationship_policy_prefix(&policy)),
        before
    );
    assert_eq!(
        module
            .edit_policy(
                &owner,
                &policy,
                &definition(false, false),
                PolicyMarshalingType::ShortYaml
            )
            .unwrap()
            .0,
        0
    );
    let restored = restore(&module);
    assert!(!can_read(&restored, &policy, "report"));
    assert_eq!(
        restored
            .query_object_owner(
                &policy,
                &Object {
                    resource: "file".into(),
                    id: "report".into()
                }
            )
            .unwrap()
            .1
            .unwrap()
            .metadata
            .owner_did,
        owner.to_string()
    );
}

#[test]
fn current_reads_ignore_many_retired_rows_during_partial_cleanup_and_restart() {
    let (mut module, owner, policy) = fixture();
    let count = retirement_cleanup::MAX_ITEMS + 32;
    let mut old_pair = None;
    for index in 0..count {
        let object = format!("doc-{index:03}");
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: object.clone(),
                }),
            )
            .unwrap();
        let record = grant(
            &mut module,
            &owner,
            &policy,
            Relationship::with_entity("file", object, "reader", Did::new(READER).unwrap()),
        );
        old_pair = Some(record.generations);
    }
    let old_pair = old_pair.unwrap();
    assert_eq!(
        module
            .edit_policy(
                &owner,
                &policy,
                &definition(false, true),
                PolicyMarshalingType::ShortYaml
            )
            .unwrap()
            .0,
        count as u64
    );
    module
        .edit_policy(
            &owner,
            &policy,
            &definition(true, true),
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    grant(
        &mut module,
        &owner,
        &policy,
        Relationship::with_entity("file", "doc-000", "reader", Did::new(READER).unwrap()),
    );
    let prefix = keys::relationship_generation_prefix(&policy, old_pair, "");
    assert_eq!(module.store.prefix_iter(&prefix).count(), count);
    // The selected live query remains below its 128-record budget despite the retained generation.
    assert_eq!(
        module
            .query_filter_relationships(&policy, &reader_selector())
            .unwrap()
            .len(),
        1
    );
    module
        .end_blocker(&BlockExecCtx {
            timestamp: Timestamp {
                block_height: 1,
                seconds: 10,
            },
            ..Default::default()
        })
        .unwrap();
    let remaining = module.store.prefix_iter(&prefix).count();
    assert!(
        remaining > 0 && remaining < count,
        "cleanup progress: {remaining}/{count}"
    );
    module = restore(&module);
    assert!(can_read(&module, &policy, "doc-000"));
    assert!(!can_read(&module, &policy, "doc-001"));
    for height in 2..=40 {
        module
            .end_blocker(&BlockExecCtx {
                timestamp: Timestamp {
                    block_height: height,
                    seconds: height * 10,
                },
                ..Default::default()
            })
            .unwrap();
        module = restore(&module);
        if module.store.prefix_iter(&prefix).next().is_none() {
            break;
        }
    }
    assert!(module.store.prefix_iter(&prefix).next().is_none());
    assert!(can_read(&module, &policy, "doc-000"));
    assert!(!can_read(&module, &policy, "doc-001"));
    assert_eq!(
        module
            .query_filter_relationships(&policy, &reader_selector())
            .unwrap()
            .len(),
        1
    );
}
