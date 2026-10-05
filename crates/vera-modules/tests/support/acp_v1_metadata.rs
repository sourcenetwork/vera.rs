use super::*;

#[test]
fn metadata_edit_and_deletion_require_policy_ownership_and_persist() {
    let (mut module, policy) = setup();
    let before = module.store().serialize();
    let metadata = SuppliedMetadata {
        attributes: [("app".into(), "documents".into())].into(),
        blob: vec![1, 2, 3],
    };
    let revision = Timestamp {
        seconds: 20,
        block_height: 2,
    };
    assert!(
        module
            .edit_policy_metadata(&did("owner"), &policy, metadata.clone(), &revision)
            .is_err()
    );
    assert!(module.delete_policy(&did("owner"), &policy).is_err());
    assert_eq!(module.store().serialize(), before);
    let original = module.query_policy(&policy).unwrap();
    let edited = module
        .edit_policy_metadata(&did("creator"), &policy, metadata.clone(), &revision)
        .unwrap();
    assert_eq!(edited.metadata, original.metadata);
    assert_eq!(edited.raw_policy, original.raw_policy);
    let mut module = restored(&module);
    assert_eq!(
        module.query_policy(&policy).unwrap().supplied_metadata,
        metadata
    );
    assert!(module.delete_policy(&did("creator"), &policy).unwrap());
    assert!(restored(&module).query_policies().unwrap().is_empty());
    assert!(!module.delete_policy(&did("creator"), &policy).unwrap());
}

#[test]
fn required_specification_and_creation_metadata_survive_restore() {
    use vera_modules::acp::types::PolicyCreation;
    let mut module = AcpModule::new();
    let mut request = PolicyCreation {
        policy: "name: files\nresources:\n  - name: file\n    permissions:\n      - name: read\n      - name: write\n".into(),
        marshal_type: PolicyMarshalingType::ShortYaml,
        required_specification: Some(zanzibar::PolicySpecification::Defra),
        metadata: SuppliedMetadata { attributes: Default::default(), blob: vec![42] },
    };
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 10,
            block_height: 1,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: did("creator").to_string(),
        tx_hash: vec![7; 32],
        sequence: 0,
    };
    let record = module
        .execute_create_policy(&did("creator"), &request, &block, &tx)
        .unwrap();
    assert_eq!(
        record.policy.specification,
        zanzibar::PolicySpecification::Defra
    );
    assert_eq!(record.supplied_metadata, request.metadata);
    assert_eq!(record.metadata.creation_ts, block.timestamp);
    restored(&module).validate_restored_state().unwrap();
    request.policy = format!("spec: defra\n{}", request.policy);
    request.required_specification = Some(zanzibar::PolicySpecification::None);
    let before = module.store().serialize();
    assert!(
        module
            .execute_create_policy(&did("creator"), &request, &block, &tx)
            .is_err()
    );
    assert_eq!(module.store().serialize(), before);
}

#[test]
fn relationship_metadata_is_stable_on_retries_transfer_and_unarchive() {
    use vera_modules::acp::types::PolicyCommandRequest;
    let (mut module, policy) = setup();
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 20,
            block_height: 2,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: did("owner").to_string(),
        tx_hash: vec![8; 32],
        sequence: 0,
    };
    let target = Object {
        resource: "file".into(),
        id: "metadata".into(),
    };
    let metadata = SuppliedMetadata {
        blob: vec![1, 2, 3],
        ..Default::default()
    };
    module
        .execute_policy_cmd_with_metadata(
            &did("owner"),
            &policy,
            PolicyCommandRequest {
                command: PolicyCmd::RegisterObject(target.clone()),
                metadata: metadata.clone(),
            },
            &block,
            &tx,
        )
        .unwrap();
    let relationship = Relationship::with_entity("file", "metadata", "reader", did("reader"));
    for supplied in [metadata.clone(), SuppliedMetadata::default()] {
        let result = module
            .execute_policy_cmd_with_metadata(
                &did("owner"),
                &policy,
                PolicyCommandRequest {
                    command: PolicyCmd::SetRelationship(relationship.clone()),
                    metadata: supplied,
                },
                &block,
                &tx,
            )
            .unwrap();
        let PolicyCmdResult::SetRelationship { record, .. } = result else {
            panic!("grant")
        };
        assert_eq!(record.supplied_metadata, metadata);
    }
    module
        .transfer_object(&did("owner"), &policy, &target, &did("next"))
        .unwrap();
    module
        .direct_policy_cmd(
            &did("next"),
            &policy,
            PolicyCmd::ArchiveObject(target.clone()),
        )
        .unwrap();
    module
        .direct_policy_cmd(
            &did("next"),
            &policy,
            PolicyCmd::UnarchiveObject(target.clone()),
        )
        .unwrap();
    let record = restored(&module)
        .query_object_registration(&policy, &target)
        .unwrap()
        .unwrap();
    assert_eq!(record.supplied_metadata, metadata);
    assert_eq!(record.metadata.creation_ts, block.timestamp);
    let before = module.store().serialize();
    assert!(
        module
            .execute_policy_cmd_with_metadata(
                &did("next"),
                &policy,
                PolicyCommandRequest {
                    command: PolicyCmd::ArchiveObject(target),
                    metadata
                },
                &block,
                &tx
            )
            .is_err()
    );
    assert_eq!(module.store().serialize(), before);
}

#[test]
fn definition_edit_prunes_incoming_usersets_before_relation_can_be_recreated() {
    let (mut module, policy) = setup();
    module
        .direct_policy_cmd(
            &did("owner"),
            &policy,
            PolicyCmd::RegisterObject(Object {
                resource: "group".into(),
                id: "admins".into(),
            }),
        )
        .unwrap();
    module
        .direct_policy_cmd(
            &did("owner"),
            &policy,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "group",
                "admins",
                "member",
                did("manager"),
            )),
        )
        .unwrap();
    module
        .direct_policy_cmd(
            &did("owner"),
            &policy,
            PolicyCmd::SetRelationship(Relationship::new(
                "file",
                "report",
                "admin",
                Subject::entity_set("group", "admins", "member"),
            )),
        )
        .unwrap();
    let replacement = POLICY
        .replace("types: [group->member]", "types: [actor]")
        .replace(
            "    relations:\n      - name: member\n        types: [actor]\n",
            "",
        );
    let revision = Timestamp {
        seconds: 20,
        block_height: 2,
    };
    let (removed, record) = module
        .edit_policy_at(
            &did("creator"),
            &policy,
            &replacement,
            PolicyMarshalingType::ShortYaml,
            &revision,
        )
        .unwrap();
    assert_eq!(removed, 2);
    assert_eq!(record.last_modified, Some(revision.clone()));
    module
        .edit_policy_at(
            &did("creator"),
            &policy,
            POLICY,
            PolicyMarshalingType::ShortYaml,
            &revision,
        )
        .unwrap();
    assert!(
        !restored(&module)
            .check_management_authority(&did("manager"), &policy, &object(), "owner")
            .unwrap()
    );
    let before = module.store().serialize();
    assert!(
        module
            .edit_policy_at(
                &did("creator"),
                &policy,
                POLICY,
                PolicyMarshalingType::ShortYaml,
                &Timestamp {
                    seconds: 19,
                    block_height: 1
                }
            )
            .is_err()
    );
    assert_eq!(module.store().serialize(), before);
}
