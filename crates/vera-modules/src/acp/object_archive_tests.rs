use super::*;

const POLICY: &str = "name: archive\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n    relations:\n      - name: member\n";
const WITHOUT_READER: &str = "name: archive\nresources:\n  - name: file\n  - name: group\n    relations:\n      - name: member\n";

fn fixture() -> (AcpModule, Did, String, Object) {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let policy = module
        .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    (module, owner, policy, object)
}

fn put(module: &mut AcpModule, policy: &str, relationship: Relationship) -> RelationshipRecord {
    let definition = module.query_policy(policy).unwrap();
    let record = RelationshipRecord {
        incarnation: object_state::for_relationship(&module.store, policy, &relationship).unwrap(),
        generations: definition.relations.pair(&relationship).unwrap(),
        policy_id: policy.into(),
        relationship,
        archived: false,
        supplied_metadata: Default::default(),
        metadata: definition.metadata,
    };
    module.set_relationship(&record).unwrap();
    record
}

fn archive(module: &mut AcpModule, owner: &Did, policy: &str, object: &Object) -> u64 {
    let result = module
        .direct_policy_cmd(owner, policy, PolicyCmd::ArchiveObject(object.clone()))
        .unwrap();
    let PolicyCmdResult::ArchiveObject {
        found: true,
        relationships_removed,
    } = result
    else {
        panic!("unexpected archive result: {result:?}");
    };
    relationships_removed
}

fn row_key(record: &RelationshipRecord) -> Vec<u8> {
    keys::relationship_generation_key(
        &record.policy_id,
        record.generations,
        &keys::relationship_storage_key(&record.relationship, record.incarnation),
    )
}

#[test]
fn archive_removes_only_outgoing_grants_and_retains_ownership() {
    let (mut module, owner, policy, object) = fixture();
    let original_owner = module
        .registration_owner_record(&policy, &object)
        .unwrap()
        .unwrap();
    let grant = put(
        &mut module,
        &policy,
        Relationship::with_entity(
            "file",
            "report",
            "reader",
            Did::new("did:key:reader").unwrap(),
        ),
    );
    let userset = put(
        &mut module,
        &policy,
        Relationship::new(
            "file",
            "report",
            "reader",
            acp::Subject::entity_set("group", "staff", "member"),
        ),
    );
    let incoming = put(
        &mut module,
        &policy,
        Relationship::new(
            "file",
            "other",
            "reader",
            acp::Subject::entity_set("file", "report", "reader"),
        ),
    );
    let unrelated = put(
        &mut module,
        &policy,
        Relationship::with_entity("file", "report-extra", "reader", owner.clone()),
    );
    assert_eq!(archive(&mut module, &owner, &policy, &object), 3);
    for record in [&grant, &userset] {
        assert!(module.store.has(&row_key(record)));
        assert!(module.store.has(&object_pairs::key(record)));
    }
    for record in [&incoming, &unrelated] {
        assert!(module.store.has(&row_key(record)));
    }
    let archived = module
        .registration_owner_record(&policy, &object)
        .unwrap()
        .unwrap();
    let mut expected_owner = original_owner.clone();
    expected_owner.archived = true;
    assert_eq!(
        serde_json::to_value(&archived).unwrap(),
        serde_json::to_value(&expected_owner).unwrap()
    );
    assert_eq!(archive(&mut module, &owner, &policy, &object), 0);
    module.validate_restored_state().unwrap();
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::UnarchiveObject(object.clone()))
        .unwrap();
    assert_eq!(
        serde_json::to_value(
            module
                .registration_owner_record(&policy, &object)
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(original_owner).unwrap()
    );
    assert!(
        module
            .get_relationship(&policy, &grant.relationship)
            .unwrap()
            .is_none()
    );
    assert!(
        module
            .get_relationship(&policy, &userset.relationship)
            .unwrap()
            .is_none()
    );
    module.validate_restored_state().unwrap();
}

#[test]
fn archive_excludes_retired_pairs_without_reviving_them_on_unarchive() {
    let without_member = "name: archive\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n";
    for (relationship, replacement) in [
        (
            Relationship::with_entity(
                "file",
                "report",
                "reader",
                Did::new("did:key:reader").unwrap(),
            ),
            WITHOUT_READER,
        ),
        (
            Relationship::new(
                "file",
                "report",
                "reader",
                acp::Subject::entity_set("group", "staff", "member"),
            ),
            without_member,
        ),
    ] {
        let (mut module, owner, policy, object) = fixture();
        let old = put(&mut module, &policy, relationship.clone());
        module
            .edit_policy(
                &owner,
                &policy,
                replacement,
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        module
            .edit_policy(&owner, &policy, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let fresh = put(&mut module, &policy, relationship.clone());
        assert_ne!(old.generations, fresh.generations);
        assert_eq!(archive(&mut module, &owner, &policy, &object), 2);
        assert!(module.store.has(&row_key(&old)));
        assert!(module.store.has(&object_pairs::key(&old)));
        assert!(module.store.has(&row_key(&fresh)));
        module.validate_restored_state().unwrap();
        module
            .direct_policy_cmd(&owner, &policy, PolicyCmd::UnarchiveObject(object.clone()))
            .unwrap();
        assert!(
            module
                .get_relationship(&policy, &relationship)
                .unwrap()
                .is_none()
        );
        module.end_blocker(&BlockExecCtx::default()).unwrap();
        assert!(!module.store.has(&row_key(&old)));
        assert!(!module.store.has(&object_pairs::key(&old)));
        module.validate_restored_state().unwrap();
    }
}

#[test]
fn invalid_accessed_archive_indexes_cannot_publish_partial_archive() {
    let (mut module, owner, policy, object) = fixture();
    let grant = put(
        &mut module,
        &policy,
        Relationship::with_entity(
            "file",
            "report",
            "reader",
            Did::new("did:key:reader").unwrap(),
        ),
    );
    let counter = object_pairs::key(&grant);
    let owner_record = module
        .registration_owner_record(&policy, &object)
        .unwrap()
        .unwrap();
    for corruption in [0, 1, 2, 3, 6] {
        let mut candidate = module.clone();
        match corruption {
            0 => candidate.store.put(&counter, 2u64.to_be_bytes().to_vec()),
            1 => candidate.store.put(&counter, 0u64.to_be_bytes().to_vec()),
            2 => candidate.store.put(&counter, vec![1]),
            3 => candidate.store.delete(&object_pairs::key(&owner_record)),
            4 => {
                let mut row = grant.clone();
                row.relationship.object_id = "elsewhere".into();
                candidate
                    .store
                    .put(&row_key(&grant), serde_json::to_vec(&row).unwrap());
            }
            5 => candidate.store.delete(&row_key(&grant)),
            6 => candidate.store.delete(&relationship_index::outgoing_key(
                &policy,
                owner_record.generations,
            )),
            _ => unreachable!(),
        }
        let before = candidate.store.serialize();
        assert!(
            candidate
                .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(object.clone()))
                .is_err(),
            "corruption {corruption}"
        );
        assert_eq!(
            candidate.store.serialize(),
            before,
            "corruption {corruption}"
        );
    }
}

#[test]
fn unauthorized_archive_preserves_rows_and_indexes() {
    let (mut module, _, policy, object) = fixture();
    let before = module.store.serialize();
    let stranger = Did::new("did:key:stranger").unwrap();
    assert!(matches!(
        module.direct_policy_cmd(&stranger, &policy, PolicyCmd::ArchiveObject(object)),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store.serialize(), before);
}
