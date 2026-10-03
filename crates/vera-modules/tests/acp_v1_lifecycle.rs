//! Policy and object lifecycle authorization, metadata and restoration.
use acp::{Relationship, Subject};
use identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        types::{
            Actor, Object, PolicyCmd, PolicyCmdResult, PolicyMarshalingType, SuppliedMetadata,
        },
    },
    kv_store::InMemoryKvStore,
    types::{BlockExecCtx, Timestamp, TxExecCtx},
};

const POLICY: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n      - name: admin\n        types: [group->member]\n        manages: [reader, owner]\n    permissions:\n      - name: read\n        expr: reader\n  - name: group\n    relations:\n      - name: member\n        types: [actor]\n";
fn did(name: &str) -> Did {
    Did::new(format!("did:key:{name}")).unwrap()
}
fn object() -> Object {
    Object {
        resource: "file".into(),
        id: "report".into(),
    }
}
fn setup() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&did("creator"), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 10,
            block_height: 1,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: did("owner").to_string(),
        tx_hash: vec![7; 32],
        sequence: 0,
    };
    module
        .execute_policy_cmd(
            &did("owner"),
            &policy,
            PolicyCmd::RegisterObject(object()),
            &block,
            &tx,
        )
        .unwrap();
    (module, policy)
}
fn restored(module: &AcpModule) -> AcpModule {
    AcpModule::from_store(InMemoryKvStore::deserialize(&module.store().serialize()).unwrap())
}

#[path = "support/acp_v1_metadata.rs"]
mod metadata;

#[test]
fn policy_creator_cannot_manage_another_actors_object() {
    let (mut module, policy) = setup();
    let before = module.store().serialize();
    let grant = Relationship::with_entity("file", "report", "reader", did("reader"));
    assert!(
        !module
            .check_management_authority(&did("creator"), &policy, &object(), "reader")
            .unwrap()
    );
    for cmd in [
        PolicyCmd::SetRelationship(grant.clone()),
        PolicyCmd::DeleteRelationship(grant),
        PolicyCmd::TransferObject {
            object: object(),
            new_owner: Actor(did("creator")),
        },
    ] {
        assert!(
            module
                .direct_policy_cmd(&did("creator"), &policy, cmd)
                .is_err()
        );
        assert_eq!(module.store().serialize(), before);
    }
    assert!(
        module
            .check_management_authority(&did("owner"), &policy, &object(), "reader")
            .unwrap()
    );
}

#[test]
fn transfer_preserves_priority_and_grants_and_revokes_old_ownership() {
    let (mut module, policy) = setup();
    let prior = module
        .query_object_registration(&policy, &object())
        .unwrap()
        .unwrap();
    let grant = Relationship::with_entity("file", "report", "reader", did("reader"));
    module
        .direct_policy_cmd(&did("owner"), &policy, PolicyCmd::SetRelationship(grant))
        .unwrap();
    let new = module
        .transfer_object(&did("owner"), &policy, &object(), &did("next"))
        .unwrap();
    assert_eq!(new.metadata.creation_ts, prior.metadata.creation_ts);
    assert_eq!(new.metadata.tx_hash, prior.metadata.tx_hash);
    assert_eq!(new.metadata.owner_did, did("next").as_str());
    let module = restored(&module);
    assert!(
        !module
            .check_management_authority(&did("owner"), &policy, &object(), "reader")
            .unwrap()
    );
    assert!(
        module
            .check_management_authority(&did("next"), &policy, &object(), "reader")
            .unwrap()
    );
    let catalogue = module.query_policy_catalogue(&policy).unwrap();
    assert_eq!(catalogue.resources["file"].object_ids.len(), 1);
    assert_eq!(
        catalogue.actors,
        vec![did("next").to_string(), did("reader").to_string()]
    );
}

#[test]
fn userset_managers_can_delegate_and_revocation_survives_restore() {
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
    let member = Relationship::with_entity("group", "admins", "member", did("manager"));
    module
        .direct_policy_cmd(
            &did("owner"),
            &policy,
            PolicyCmd::SetRelationship(member.clone()),
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
    assert!(
        restored(&module)
            .check_management_authority(&did("manager"), &policy, &object(), "reader")
            .unwrap()
    );
    module
        .direct_policy_cmd(
            &did("owner"),
            &policy,
            PolicyCmd::DeleteRelationship(member),
        )
        .unwrap();
    assert!(
        !restored(&module)
            .check_management_authority(&did("manager"), &policy, &object(), "reader")
            .unwrap()
    );
}

#[test]
fn missing_and_archived_objects_cannot_transfer_or_gain_new_grants() {
    let (mut module, policy) = setup();
    module
        .direct_policy_cmd(&did("owner"), &policy, PolicyCmd::ArchiveObject(object()))
        .unwrap();
    let before = module.store().serialize();
    for obj in [
        object(),
        Object {
            resource: "file".into(),
            id: "missing".into(),
        },
    ] {
        assert!(
            module
                .transfer_object(&did("owner"), &policy, &obj, &did("next"))
                .is_err()
        );
        assert!(
            !module
                .check_management_authority(&did("owner"), &policy, &obj, "reader")
                .unwrap()
        );
    }
    assert_eq!(module.store().serialize(), before);
    assert!(
        module
            .query_object_registration(&policy, &object())
            .unwrap()
            .unwrap()
            .archived
    );
}

#[test]
fn transfer_command_has_a_typed_result() {
    let (mut module, policy) = setup();
    let result = module
        .direct_policy_cmd(
            &did("owner"),
            &policy,
            PolicyCmd::TransferObject {
                object: object(),
                new_owner: Actor(did("next")),
            },
        )
        .unwrap();
    assert!(
        matches!(result, PolicyCmdResult::TransferObject { record } if record.metadata.owner_did == did("next").as_str())
    );
}

#[test]
fn policy_deletion_removes_only_its_registration_indexes() {
    let (mut module, policy) = setup();
    let other = module
        .create_policy(&did("creator"), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let mut ids = Vec::new();
    for target in [&policy, &other] {
        let result = module
            .direct_policy_cmd(
                &did("owner"),
                target,
                PolicyCmd::CommitRegistrations {
                    commitment: vec![7; 32],
                },
            )
            .unwrap();
        let PolicyCmdResult::CommitRegistrations {
            registrations_commitment,
        } = result
        else {
            panic!("commitment")
        };
        ids.push(registrations_commitment.id);
    }
    module.delete_policy(&did("creator"), &policy).unwrap();
    let module = restored(&module);
    module.validate_restored_state().unwrap();
    assert!(module.query_registrations_commitment(ids[0]).is_err());
    assert_eq!(
        module
            .query_registrations_commitment(ids[1])
            .unwrap()
            .policy_id,
        other
    );
}

#[test]
fn theorem_results_cover_denial_management_ranges_and_invalid_inputs() {
    use vera_modules::acp::theorem::TheoremStatus;
    let (module, policy) = setup();
    let source = "Authorizations { file:report#read@did:key:owner !file:report#read@did:key:stranger }\nDelegations { did:key:owner > file:report#reader !did:key:creator > file:report#reader }";
    let report = module.evaluate_theorem(&policy, source).unwrap();
    assert!(report.ok);
    assert_eq!(report.theorem_count, 4);
    for result in report.results {
        assert_eq!(result.status, TheoremStatus::Accept);
        assert!(!source[result.theorem.start..result.theorem.end].is_empty());
    }
    let rejected = module
        .evaluate_theorem(
            &policy,
            "Authorizations { file:report#read@did:key:stranger } Delegations {}",
        )
        .unwrap();
    assert!(!rejected.ok);
    assert_eq!(rejected.failures, 1);
    assert_eq!(rejected.results[0].status, TheoremStatus::Reject);
    let bad = module
        .evaluate_theorem(
            &policy,
            "Authorizations { file:report#unknown@did:key:owner } Delegations {}",
        )
        .unwrap();
    assert_eq!(bad.results[0].status, TheoremStatus::Error);
    for malformed in [
        "",
        "Authorizations {}",
        "Authorizations {} Delegations {} trailing",
        "Authorizations {} Delegations {} ImpliedRelations { file:report#read => file:report#write }",
        "Authorizations { file:report#read@group:admins#member } Delegations {}",
    ] {
        assert!(
            module.evaluate_theorem(&policy, malformed).is_err(),
            "{malformed}"
        );
    }
    let oversized = format!(
        "Authorizations {{ {} }} Delegations {{}}",
        "file:report#read@did:key:owner ".repeat(65)
    );
    assert!(module.evaluate_theorem(&policy, &oversized).is_err());
}
