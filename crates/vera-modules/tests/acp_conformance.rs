//! Ownership and revocation cases from Vera 205df1ad (acp_core v0.8.2).
//! Reference: https://github.com/sourcenetwork/vera/tree/205df1ad/tests/integration/acp/suite

use vera_acp::Relationship;
use vera_identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        error::AcpError,
        types::{
            AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyCmdResult,
            PolicyMarshalingType,
        },
    },
    kv_store::InMemoryKvStore,
};

const POLICY: &str = r#"
name: documents
resources:
  - name: file
    relations:
      - name: reader
        types: [actor]
      - name: writer
        types: [actor]
      - name: admin
        types: [actor]
        manages: [reader]
    permissions:
      - name: read
        expr: reader
"#;

fn owner() -> Did {
    Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap()
}

fn reader() -> Did {
    Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap()
}

fn object() -> Object {
    Object {
        resource: "file".into(),
        id: "report".into(),
    }
}

fn restore(module: &AcpModule) -> AcpModule {
    AcpModule::from_store(InMemoryKvStore::deserialize(&module.store().serialize()).unwrap())
}

fn setup() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap();
    module
        .direct_policy_cmd(
            &owner(),
            &policy.policy.id,
            PolicyCmd::RegisterObject(object()),
        )
        .unwrap();
    (module, policy.policy.id)
}

#[test]
fn check_access_rejects_invalid_context_missing_policies_and_partial_denials() {
    use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};

    let read_on = |id: &str| Operation {
        object: Object {
            resource: "file".into(),
            id: id.into(),
        },
        permission: "read".into(),
    };
    let context = |height: u64, seconds: u64| BlockExecCtx {
        genesis_id: [7; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds,
            block_height: height,
        },
    };
    let submission = |signer: &str, sequence: u64| TxExecCtx {
        sequence,
        tx_hash: vec![9; 32],
        signer: signer.into(),
    };
    let (mut module, policy_id) = setup();
    module
        .direct_policy_cmd(
            &owner(),
            &policy_id,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "file",
                "report",
                "reader",
                reader(),
            )),
        )
        .unwrap();
    let granted = AccessRequest {
        actor: Actor(reader()),
        operations: vec![read_on("report")],
    };
    let before = module.store().serialize();
    for (height, seconds, signer) in [
        (0, 100, "did:key:owner"),
        (5, 0, "did:key:owner"),
        (5, 100, "did:key:other"),
    ] {
        assert!(matches!(
            module.check_access(
                &owner(),
                &policy_id,
                &granted,
                &context(height, seconds),
                &submission(signer, 0),
            ),
            Err(AcpError::InvalidAccessRequest { .. })
        ));
    }
    assert!(matches!(
        module.check_access(
            &owner(),
            "missing-policy",
            &granted,
            &context(5, 100),
            &submission(owner().as_str(), 0),
        ),
        Err(AcpError::PolicyNotFound { .. })
    ));
    let unknown_resource = AccessRequest {
        actor: Actor(reader()),
        operations: vec![Operation {
            object: Object {
                resource: "unknown".into(),
                id: "report".into(),
            },
            permission: "read".into(),
        }],
    };
    let denied_first = AccessRequest {
        actor: Actor(reader()),
        operations: vec![read_on("other")],
    };
    let denied_second = AccessRequest {
        actor: Actor(reader()),
        operations: vec![read_on("report"), read_on("other")],
    };
    for request in [&unknown_resource, &denied_first, &denied_second] {
        assert!(matches!(
            module.check_access(
                &owner(),
                &policy_id,
                request,
                &context(5, 100),
                &submission(owner().as_str(), 0),
            ),
            Err(AcpError::Unauthorized { .. }) | Err(AcpError::State(_))
        ));
        assert_eq!(module.store().serialize(), before);
    }
    let decision = module
        .check_access(
            &owner(),
            &policy_id,
            &granted,
            &context(5, 100),
            &submission(owner().as_str(), 3),
        )
        .unwrap();
    assert_eq!(decision.actor, reader().to_string());
    assert_eq!(decision.creator, owner().to_string());
    assert_eq!(decision.creator_acc_sequence, 3);
    assert_eq!(
        module.query_access_decision(&decision.id).unwrap().as_ref(),
        Some(&decision)
    );
    let replayed = module
        .check_access(
            &owner(),
            &policy_id,
            &granted,
            &context(6, 101),
            &submission(owner().as_str(), 3),
        )
        .unwrap();
    assert_eq!(replayed.id, decision.id);
    assert_eq!(replayed.operations, decision.operations);
}

#[test]
fn edit_and_read_policy_guards_reject_without_side_effects() {
    use vera_modules::acp::types::PolicyMarshalingType;

    let mut module = AcpModule::new();
    let policy_id = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let before = module.store().serialize();
    assert!(matches!(
        module.query_policy("missing-policy"),
        Err(AcpError::PolicyNotFound { .. })
    ));
    assert!(matches!(
        module.edit_policy(
            &reader(),
            &policy_id,
            POLICY,
            PolicyMarshalingType::ShortYaml
        ),
        Err(AcpError::Unauthorized { .. })
    ));
    assert!(matches!(
        module.edit_policy(
            &owner(),
            "missing-policy",
            POLICY,
            PolicyMarshalingType::ShortYaml
        ),
        Err(AcpError::PolicyNotFound { .. })
    ));
    let shrunk = "name: shrunk\nresources:\n  - name: other\n";
    assert!(
        module
            .edit_policy(
                &owner(),
                &policy_id,
                shrunk,
                PolicyMarshalingType::ShortYaml
            )
            .is_err()
    );
    assert!(matches!(
        module.edit_policy(&owner(), &policy_id, POLICY, PolicyMarshalingType::Unknown),
        Err(AcpError::InvalidPolicy { .. })
    ));
    assert_eq!(module.store().serialize(), before);
    let (removed, record) = module
        .edit_policy(
            &owner(),
            &policy_id,
            "name: edited\nresources:\n  - name: file\n  - name: other\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    assert_eq!(removed, 0);
    assert_eq!(record.metadata.owner_did, owner().to_string());
    let restored = restore(&module);
    let serialized = serde_json::to_value(&record).unwrap();
    assert_eq!(
        serde_json::to_value(restored.query_policy(&policy_id).unwrap()).unwrap(),
        serialized
    );
}

#[test]
fn registration_errors_preserve_state_and_object_identity_after_restore() {
    let (module, policy) = setup();
    for mut candidate in [module.clone(), restore(&module)] {
        let before = candidate.store().serialize();
        for (resource, id) in [("file", ""), ("", "report"), ("missing", "report")] {
            assert!(matches!(
                candidate.direct_policy_cmd(
                    &reader(),
                    &policy,
                    PolicyCmd::RegisterObject(Object {
                        resource: resource.into(),
                        id: id.into(),
                    }),
                ),
                Err(AcpError::InvalidAccessRequest { .. })
            ));
            assert_eq!(candidate.store().serialize(), before);
        }
        assert!(matches!(
            candidate.direct_policy_cmd(
                &reader(),
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "actor".into(),
                    id: reader().to_string(),
                }),
            ),
            Err(AcpError::Unauthorized { .. })
        ));
        assert_eq!(candidate.store().serialize(), before);
        assert!(matches!(
            candidate.direct_policy_cmd(
                &reader(),
                "missing-policy",
                PolicyCmd::RegisterObject(object()),
            ),
            Err(AcpError::PolicyNotFound { .. })
        ));
        assert_eq!(candidate.store().serialize(), before);
        for actor in [owner(), reader()] {
            assert!(
                candidate
                    .direct_policy_cmd(&actor, &policy, PolicyCmd::RegisterObject(object()))
                    .is_err()
            );
            assert_eq!(candidate.store().serialize(), before);
        }
        let distinct = Object {
            resource: "file".into(),
            id: "report/child:α".into(),
        };
        candidate
            .direct_policy_cmd(
                &reader(),
                &policy,
                PolicyCmd::RegisterObject(distinct.clone()),
            )
            .unwrap();
        let restored = restore(&candidate);
        for (object, actor) in [(object(), owner()), (distinct, reader())] {
            let (registered, record) = restored.query_object_owner(&policy, &object).unwrap();
            assert!(registered);
            assert_eq!(record.unwrap().metadata.owner_did, actor.to_string());
        }
    }
}

fn can_read(module: &AcpModule, policy_id: &str) -> bool {
    module
        .query_verify_access_request(
            policy_id,
            &AccessRequest {
                actor: Actor(reader()),
                operations: vec![Operation {
                    object: object(),
                    permission: "read".into(),
                }],
            },
        )
        .unwrap()
}

#[test]
fn archived_objects_remain_reserved_after_restore() {
    let (mut module, policy_id) = setup();
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::ArchiveObject(object()))
        .unwrap();

    for mut candidate in [module.clone(), restore(&module)] {
        for actor in [owner(), reader()] {
            let before = candidate.store().serialize();
            let result = candidate.direct_policy_cmd(
                &actor,
                &policy_id,
                PolicyCmd::RegisterObject(object()),
            );
            assert!(
                matches!(result, Err(AcpError::ObjectAlreadyRegistered { .. })),
                "{result:?}"
            );
            assert_eq!(candidate.store().serialize(), before);
        }
        assert!(
            candidate
                .direct_policy_cmd(&reader(), &policy_id, PolicyCmd::UnarchiveObject(object()))
                .is_err()
        );
        candidate
            .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::UnarchiveObject(object()))
            .unwrap();
        let (registered, record) = candidate.query_object_owner(&policy_id, &object()).unwrap();
        assert!(registered);
        assert_eq!(record.unwrap().metadata.owner_did, owner().to_string());
    }
}

#[test]
fn revocation_survives_restore_and_stays_within_its_policy() {
    let (mut module, policy_id) = setup();
    let other_policy = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    module
        .direct_policy_cmd(&owner(), &other_policy, PolicyCmd::RegisterObject(object()))
        .unwrap();
    let grant = Relationship::with_entity("file", "report", "reader", reader());
    for id in [&policy_id, &other_policy] {
        module
            .direct_policy_cmd(&owner(), id, PolicyCmd::SetRelationship(grant.clone()))
            .unwrap();
        assert!(can_read(&module, id));
    }

    let before = module.store().serialize();
    assert!(matches!(
        module.direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::DeleteRelationship(grant.clone())
        ),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store().serialize(), before);
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::DeleteRelationship(grant))
        .unwrap();

    for candidate in [module.clone(), restore(&module)] {
        assert!(!can_read(&candidate, &policy_id));
        assert!(can_read(&candidate, &other_policy));
    }
}

#[test]
fn delegated_management_is_limited_to_declared_relations() {
    let (mut module, policy_id) = setup();
    for relation in ["reader", "writer", "admin"] {
        module
            .direct_policy_cmd(
                &owner(),
                &policy_id,
                PolicyCmd::SetRelationship(Relationship::with_entity(
                    "file",
                    "report",
                    relation,
                    reader(),
                )),
            )
            .unwrap();
    }
    let mut module = restore(&module);
    let before = module.store().serialize();
    assert!(matches!(
        module.direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::DeleteRelationship(Relationship::with_entity(
                "file",
                "report",
                "writer",
                reader()
            ))
        ),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store().serialize(), before);
    module
        .direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::DeleteRelationship(Relationship::with_entity(
                "file",
                "report",
                "reader",
                reader(),
            )),
        )
        .unwrap();
    assert!(!can_read(&module, &policy_id));
}

#[test]
fn commitment_opening_cannot_reactivate_an_archived_object() {
    let mut module = AcpModule::new();
    let policy_id = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let opening = module
        .query_generate_commitment(&policy_id, &[object()], &Actor(reader()))
        .unwrap();
    let result = module
        .direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::CommitRegistrations {
                commitment: opening.commitment,
            },
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = result
    else {
        panic!("unexpected result: {result:?}");
    };
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::RegisterObject(object()))
        .unwrap();
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::ArchiveObject(object()))
        .unwrap();

    for mut candidate in [module.clone(), restore(&module)] {
        let before = candidate.store().serialize();
        assert!(matches!(
            candidate.query_generate_commitment(&policy_id, &[object()], &Actor(reader())),
            Err(AcpError::ObjectAlreadyRegistered { .. })
        ));
        let result = candidate.direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: opening.proofs[0].clone(),
            },
        );
        assert!(
            matches!(result, Err(AcpError::ObjectAlreadyRegistered { .. })),
            "{result:?}"
        );
        assert_eq!(candidate.store().serialize(), before);
    }
}

#[test]
fn policy_edits_preserve_defra_specification_across_restore() {
    let definition = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n      - name: writer\n    permissions:\n      - name: read\n        expr: reader\n      - name: write\n        expr: writer\n";
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(
            &owner(),
            &format!("spec: defra\n{definition}"),
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    module
        .direct_policy_cmd(&owner(), &policy, PolicyCmd::RegisterObject(object()))
        .unwrap();
    module
        .direct_policy_cmd(
            &owner(),
            &policy,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "file",
                "report",
                "writer",
                reader(),
            )),
        )
        .unwrap();
    assert!(can_read(&module, &policy));

    for spec in ["", "spec: none\n", "spec: defra\n"] {
        module = restore(&module);
        module
            .edit_policy(
                &owner(),
                &policy,
                &format!("{spec}{definition}"),
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        assert!(can_read(&module, &policy));
        assert!(can_read(&restore(&module), &policy));
        let before = module.store().serialize();
        let invalid = definition.replace("      - name: write\n        expr: writer\n", "");
        assert!(
            module
                .edit_policy(&owner(), &policy, &invalid, PolicyMarshalingType::ShortYaml)
                .is_err()
        );
        assert_eq!(module.store().serialize(), before);
    }
}

#[test]
fn actor_roles_require_management_authority_without_object_registration() {
    let mut module = AcpModule::new();
    let definition = "name: files\nactor:\n  relations:\n    - name: member\n      types: [actor]\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor->member]\n    permissions:\n      - name: read\n        expr: reader\n";
    let policy = module
        .create_policy(&owner(), definition, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let actor = Object {
        resource: "actor".into(),
        id: reader().to_string(),
    };
    for caller in [owner(), reader()] {
        assert!(
            module
                .direct_policy_cmd(&caller, &policy, PolicyCmd::RegisterObject(actor.clone()))
                .is_err()
        );
    }
    let role = Relationship::with_entity("actor", &actor.id, "member", reader());
    assert!(
        module
            .direct_policy_cmd(&reader(), &policy, PolicyCmd::SetRelationship(role.clone()))
            .is_err()
    );
    module
        .direct_policy_cmd(&owner(), &policy, PolicyCmd::SetRelationship(role.clone()))
        .unwrap();
    module
        .direct_policy_cmd(&owner(), &policy, PolicyCmd::RegisterObject(object()))
        .unwrap();
    module
        .direct_policy_cmd(
            &owner(),
            &policy,
            PolicyCmd::SetRelationship(Relationship::new(
                "file",
                "report",
                "reader",
                vera_acp::Subject::entity_set("actor", &actor.id, "member"),
            )),
        )
        .unwrap();
    assert!(can_read(&restore(&module), &policy));
    assert!(
        module
            .direct_policy_cmd(
                &owner(),
                &policy,
                PolicyCmd::SetRelationship(Relationship::with_entity(
                    "actor",
                    "invalid-id",
                    "member",
                    reader()
                ))
            )
            .is_err()
    );
    module
        .direct_policy_cmd(&owner(), &policy, PolicyCmd::DeleteRelationship(role))
        .unwrap();
    assert!(!can_read(&restore(&module), &policy));
}

#[test]
fn access_query_distinguishes_missing_policy_from_denial() {
    let (module, policy_id) = setup();
    let mut request = AccessRequest {
        actor: Actor(reader()),
        operations: vec![Operation {
            object: object(),
            permission: "read".into(),
        }],
    };
    let before = module.store().serialize();
    assert!(
        !module
            .query_verify_access_request(&policy_id, &request)
            .unwrap()
    );
    for empty in [false, true] {
        if empty {
            request.operations.clear();
            assert!(
                module
                    .query_verify_access_request(&policy_id, &request)
                    .unwrap()
            );
        }
        assert!(matches!(
            module.query_verify_access_request("missing-policy", &request),
            Err(AcpError::PolicyNotFound { id }) if id == "missing-policy"
        ));
    }
    assert_eq!(module.store().serialize(), before);
}

#[test]
fn duplicate_relationship_preserves_original_metadata() {
    use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};

    let (mut module, policy_id) = setup();
    let relationship = Relationship::with_entity("file", "report", "reader", reader());
    let mut block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 100,
            block_height: 10,
        },
        ..Default::default()
    };
    let mut submission = TxExecCtx {
        signer: owner().to_string(),
        tx_hash: vec![1; 32],
        sequence: 1,
    };
    let original = module
        .execute_policy_cmd(
            &owner(),
            &policy_id,
            PolicyCmd::SetRelationship(relationship.clone()),
            &block,
            &submission,
        )
        .unwrap();
    let PolicyCmdResult::SetRelationship {
        record_existed: false,
        record,
    } = original
    else {
        panic!("expected new relationship");
    };
    let encoded = serde_json::to_value(&record).unwrap();
    block.timestamp = Timestamp {
        seconds: 200,
        block_height: 20,
    };
    submission.tx_hash = vec![2; 32];
    for mut candidate in [module.clone(), restore(&module)] {
        let before = candidate.store().serialize();
        let result = candidate
            .execute_policy_cmd(
                &owner(),
                &policy_id,
                PolicyCmd::SetRelationship(relationship.clone()),
                &block,
                &submission,
            )
            .unwrap();
        let PolicyCmdResult::SetRelationship {
            record_existed: true,
            record,
        } = result
        else {
            panic!("expected existing relationship");
        };
        assert_eq!(serde_json::to_value(&record).unwrap(), encoded);
        assert_eq!(candidate.store().serialize(), before);
        assert!(matches!(
            candidate.execute_policy_cmd(
                &reader(),
                &policy_id,
                PolicyCmd::SetRelationship(relationship.clone()),
                &block,
                &submission,
            ),
            Err(AcpError::Unauthorized { .. })
        ));
        assert_eq!(candidate.store().serialize(), before);
    }
}

#[test]
fn archive_results_preserve_registration_and_object_boundaries() {
    let (mut module, policy_id) = setup();
    let neighbor = Object {
        resource: "file".into(),
        id: "report/child".into(),
    };
    module
        .direct_policy_cmd(
            &owner(),
            &policy_id,
            PolicyCmd::RegisterObject(neighbor.clone()),
        )
        .unwrap();
    module
        .direct_policy_cmd(
            &owner(),
            &policy_id,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "file",
                "report",
                "reader",
                reader(),
            )),
        )
        .unwrap();
    let before = module.store().serialize();
    for cmd in [
        PolicyCmd::ArchiveObject(object()),
        PolicyCmd::UnarchiveObject(object()),
    ] {
        assert!(matches!(
            module.direct_policy_cmd(&owner(), "missing", cmd),
            Err(AcpError::PolicyNotFound { .. })
        ));
    }
    assert!(matches!(
        module.direct_policy_cmd(
            &owner(),
            &policy_id,
            PolicyCmd::ArchiveObject(Object {
                resource: "file".into(),
                id: "missing".into()
            },)
        ),
        Err(AcpError::ObjectNotRegistered { .. })
    ));
    assert!(matches!(
        module.direct_policy_cmd(&reader(), &policy_id, PolicyCmd::ArchiveObject(object())),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store().serialize(), before);
    assert!(matches!(
        module
            .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::ArchiveObject(object()))
            .unwrap(),
        PolicyCmdResult::ArchiveObject {
            found: true,
            relationships_removed: 2
        }
    ));
    for mut candidate in [module.clone(), restore(&module)] {
        let before = candidate.store().serialize();
        assert!(matches!(
            candidate
                .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::ArchiveObject(object()))
                .unwrap(),
            PolicyCmdResult::ArchiveObject {
                found: true,
                relationships_removed: 0
            }
        ));
        assert_eq!(candidate.store().serialize(), before);
        assert!(
            candidate
                .query_object_owner(&policy_id, &neighbor)
                .unwrap()
                .0
        );
        for modified in [true, false] {
            let result = candidate
                .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::UnarchiveObject(object()))
                .unwrap();
            assert!(
                matches!(result, PolicyCmdResult::UnarchiveObject { relationship_modified, .. } if relationship_modified == modified)
            );
        }
        assert!(!can_read(&candidate, &policy_id));
    }
}

#[test]
fn cyclic_exclusions_cannot_create_successful_access_decisions() {
    use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};

    let mut module = AcpModule::new();
    let policy = module.create_policy(
        &owner(),
        "name: exclusions\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader - excluded\n      - name: excluded\n        expr: read\n",
        PolicyMarshalingType::ShortYaml,
    ).unwrap();
    let id = policy.policy.id;
    for command in [
        PolicyCmd::RegisterObject(object()),
        PolicyCmd::SetRelationship(Relationship::with_entity(
            "file",
            "report",
            "reader",
            reader(),
        )),
    ] {
        module.direct_policy_cmd(&owner(), &id, command).unwrap();
    }
    let request = AccessRequest {
        actor: Actor(reader()),
        operations: vec![Operation {
            object: object(),
            permission: "read".into(),
        }],
    };
    let block = BlockExecCtx {
        genesis_id: [7; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 100,
            block_height: 5,
        },
    };
    let tx = TxExecCtx {
        sequence: 0,
        tx_hash: vec![9; 32],
        signer: owner().to_string(),
    };
    for mut candidate in [module.clone(), restore(&module)] {
        candidate.validate_restored_state().unwrap();
        let before = candidate.store().serialize();
        assert!(
            candidate
                .query_verify_access_request(&id, &request)
                .is_err()
        );
        assert!(
            candidate
                .check_access(&owner(), &id, &request, &block, &tx)
                .is_err()
        );
        assert_eq!(candidate.store().serialize(), before);
    }
}
