use super::*;

fn setup() -> (AcpModule, Did, Did, String, Object) {
    let first = Did::new("did:key:first").unwrap();
    let second = Did::new("did:key:second").unwrap();
    let mut module = AcpModule::new();
    let policy = module.create_policy(
        &first,
        "name: registrations\nresources:\n  - name: file\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: owner\n",
        PolicyMarshalingType::ShortYaml,
    ).unwrap().policy.id;
    (
        module,
        first,
        second,
        policy,
        Object {
            resource: "file".into(),
            id: "report".into(),
        },
    )
}

#[test]
fn unarchive_errors_preserve_state_before_and_after_restoration() {
    let (mut module, policy_owner, object_owner, policy, object) = setup();
    module
        .direct_policy_cmd(
            &object_owner,
            &policy,
            PolicyCmd::RegisterObject(object.clone()),
        )
        .unwrap();
    for archived in [false, true] {
        if archived {
            module
                .direct_policy_cmd(
                    &object_owner,
                    &policy,
                    PolicyCmd::ArchiveObject(object.clone()),
                )
                .unwrap();
        }
        let before = module.store.serialize();
        for mut candidate in [
            module.clone(),
            AcpModule::from_store(InMemoryKvStore::deserialize(&before).unwrap()),
        ] {
            assert!(matches!(
                candidate.direct_policy_cmd(
                    &object_owner,
                    &"f".repeat(64),
                    PolicyCmd::UnarchiveObject(object.clone()),
                ),
                Err(AcpError::PolicyNotFound { .. })
            ));
            assert_eq!(candidate.store.serialize(), before);
            for missing in [
                Object {
                    resource: object.resource.clone(),
                    id: "missing".into(),
                },
                Object {
                    resource: "missing".into(),
                    id: object.id.clone(),
                },
            ] {
                assert!(matches!(
                    candidate.direct_policy_cmd(
                        &object_owner,
                        &policy,
                        PolicyCmd::UnarchiveObject(missing),
                    ),
                    Err(AcpError::ObjectNotRegistered { .. })
                ));
                assert_eq!(candidate.store.serialize(), before);
            }
            assert!(matches!(
                candidate.direct_policy_cmd(
                    &policy_owner,
                    &policy,
                    PolicyCmd::UnarchiveObject(object.clone()),
                ),
                Err(AcpError::Unauthorized { .. })
            ));
            assert_eq!(candidate.store.serialize(), before);
            let result = candidate
                .direct_policy_cmd(
                    &object_owner,
                    &policy,
                    PolicyCmd::UnarchiveObject(object.clone()),
                )
                .unwrap();
            let PolicyCmdResult::UnarchiveObject {
                record,
                relationship_modified,
            } = result
            else {
                panic!("unexpected unarchive result");
            };
            assert_eq!(relationship_modified, archived);
            assert!(!record.archived);
            assert_eq!(record.metadata.owner_did, object_owner.to_string());
            if !archived {
                assert_eq!(candidate.store.serialize(), before);
            }
        }
    }
}

#[test]
fn amendment_moves_the_owner_key_and_revokes_the_previous_owner() {
    let (mut module, first, second, policy, object) = setup();
    let generated = module
        .query_generate_commitment(
            &policy,
            std::slice::from_ref(&object),
            &Actor(second.clone()),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = module
        .direct_policy_cmd(
            &second,
            &policy,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
        )
        .unwrap()
    else {
        panic!("expected commitment")
    };
    module
        .direct_policy_cmd(&first, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    assert!(
        module
            .permission_engine(&module.zanzibar_policies[&policy])
            .check_blocking(&policy, "file", "report", "read", &first)
            .unwrap()
    );
    let PolicyCmdResult::RevealRegistration {
        record,
        event: Some(event),
    } = module
        .direct_policy_cmd(
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: generated.proofs[0].clone(),
            },
        )
        .unwrap()
    else {
        panic!("expected amendment")
    };
    assert_eq!(event.previous_owner.0, first);
    assert_eq!(event.new_owner.0, second);
    let old = Relationship::with_entity("file", "report", "owner", first.clone());
    assert!(!module.has_relationship(&policy, &keys::relationship_storage_key(&old)));
    let stored = module
        .get_relationship(&policy, &record.relationship)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(stored).unwrap(),
        serde_json::to_value(&record).unwrap()
    );
    assert_eq!(
        serde_json::to_value(
            module
                .query_object_owner(&policy, &object)
                .unwrap()
                .1
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(&record).unwrap()
    );
    assert!(
        module
            .permission_engine(&module.zanzibar_policies[&policy])
            .check_blocking(&policy, "file", "report", "read", &second)
            .unwrap()
    );
    assert!(
        !module
            .permission_engine(&module.zanzibar_policies[&policy])
            .check_blocking(&policy, "file", "report", "read", &first)
            .unwrap()
    );
    assert!(
        module
            .direct_policy_cmd(&first, &policy, PolicyCmd::ArchiveObject(object.clone()))
            .is_err()
    );
    module
        .direct_policy_cmd(&second, &policy, PolicyCmd::ArchiveObject(object.clone()))
        .unwrap();
    module
        .direct_policy_cmd(&second, &policy, PolicyCmd::UnarchiveObject(object))
        .unwrap();
}

#[test]
fn reveal_cannot_reassign_a_commitment_to_another_policy() {
    let (mut module, first, second, policy, object) = setup();
    let other = module
        .create_policy(
            &first,
            "name: other\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let generated = module
        .query_generate_commitment(&policy, &[object], &Actor(second.clone()))
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = module
        .direct_policy_cmd(
            &second,
            &other,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
        )
        .unwrap()
    else {
        panic!("expected commitment")
    };
    let before = module.store.serialize();
    let error = module
        .direct_policy_cmd(
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: generated.proofs[0].clone(),
            },
        )
        .unwrap_err();
    assert!(matches!(error, AcpError::InvalidProof { .. }));
    assert_eq!(module.store.serialize(), before);
}

fn execute(
    module: &mut AcpModule,
    actor: &Did,
    policy: &str,
    command: PolicyCmd,
    height: u64,
) -> Result<PolicyCmdResult> {
    module.execute_policy_cmd(
        actor,
        policy,
        command,
        &BlockExecCtx {
            genesis_id: [1; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                block_height: height,
                seconds: height + 100,
            },
        },
        &TxExecCtx {
            signer: actor.to_string(),
            tx_hash: vec![height as u8; 32],
            sequence: height,
        },
    )
}

#[test]
fn registration_priority_uses_committed_revisions_and_survives_amendment() {
    let (mut module, first, second, policy, object) = setup();
    let generated = module
        .query_generate_commitment(
            &policy,
            std::slice::from_ref(&object),
            &Actor(second.clone()),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment: early,
    } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment.clone(),
        },
        10,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        20,
    )
    .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment: late,
    } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        30,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    let before = module.store.serialize();
    assert!(matches!(
        execute(
            &mut module,
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: late.id,
                proof: generated.proofs[0].clone(),
            },
            31
        ),
        Err(AcpError::InvalidProof { .. })
    ));
    assert_eq!(module.store.serialize(), before);
    let PolicyCmdResult::RevealRegistration {
        record,
        event: Some(event),
    } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: early.id,
            proof: generated.proofs[0].clone(),
        },
        32,
    )
    .unwrap()
    else {
        panic!("expected amendment")
    };
    assert_eq!(record.metadata.creation_ts.block_height, 10);
    assert_eq!(record.metadata.tx_hash, vec![32; 32]);
    assert_eq!(event.metadata.creation_ts.block_height, 32);
    assert_eq!(
        module
            .query_object_owner(&policy, &object)
            .unwrap()
            .1
            .unwrap()
            .metadata
            .creation_ts
            .block_height,
        10
    );
    let before = module.store.serialize();
    assert!(
        execute(
            &mut module,
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: late.id,
                proof: generated.proofs[0].clone(),
            },
            33
        )
        .is_err()
    );
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn registration_leaf_binds_object_field_boundaries() {
    let (mut module, first, second, _, _) = setup();
    let policy = module
        .create_policy(
            &first,
            "name: boundaries\nresources:\n  - name: a\n  - name: ab\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "a".into(),
        id: "bc".into(),
    };
    let generated = module
        .query_generate_commitment(&policy, &[object], &Actor(second.clone()))
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        10,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    let mut substituted = generated.proofs[0].clone();
    substituted.object = Object {
        resource: "ab".into(),
        id: "c".into(),
    };
    let before = module.store.serialize();
    assert!(matches!(
        execute(
            &mut module,
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: substituted,
            },
            11
        ),
        Err(AcpError::InvalidProof { .. })
    ));
    assert_eq!(module.store.serialize(), before);
    execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        },
        11,
    )
    .unwrap();
}

#[test]
fn registration_proofs_support_odd_trees_and_reject_invalid_shapes() {
    let (module, _, actor, policy, _) = setup();
    for count in [1, 2, 3, 5, 6] {
        let objects: Vec<_> = (0..count)
            .map(|index| Object {
                resource: "file".into(),
                id: index.to_string(),
            })
            .collect();
        let generated = module
            .query_generate_commitment(&policy, &objects, &Actor(actor.clone()))
            .unwrap();
        for proof in &generated.proofs {
            let leaf =
                AcpModule::registration_leaf(&policy, &proof.object, actor.as_str()).unwrap();
            assert!(AcpModule::verify_merkle_proof(
                &generated.commitment,
                proof,
                &leaf
            ));
            let mut bad = proof.clone();
            bad.leaf_count = 0;
            assert!(!AcpModule::verify_merkle_proof(
                &generated.commitment,
                &bad,
                &leaf
            ));
            bad = proof.clone();
            bad.leaf_index = bad.leaf_count;
            assert!(!AcpModule::verify_merkle_proof(
                &generated.commitment,
                &bad,
                &leaf
            ));
            bad = proof.clone();
            bad.merkle_proof.push(vec![0; 32]);
            assert!(!AcpModule::verify_merkle_proof(
                &generated.commitment,
                &bad,
                &leaf
            ));
        }
    }
}

#[test]
fn default_commitment_expires_after_ten_minutes() {
    let (mut module, actor, _, policy, _) = setup();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = execute(
        &mut module,
        &actor,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: vec![1; 32],
        },
        10,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    let mut context = BlockExecCtx {
        genesis_id: [1; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            block_height: 11,
            seconds: 710,
        },
    };
    assert!(module.end_blocker(&context).unwrap().is_empty());
    context.timestamp.seconds += 1;
    let expired = module.end_blocker(&context).unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].id, registrations_commitment.id);
    assert!(expired[0].expired);
}

#[test]
fn reveal_checks_deadline_without_waiting_for_cleanup() {
    for validity in [Duration::Seconds(600), Duration::Blocks(600)] {
        let (mut module, actor, _, policy, object) = setup();
        module
            .set_params(&AcpParams {
                registrations_commitment_validity: validity,
                ..AcpParams::default()
            })
            .unwrap();
        let generated = module
            .query_generate_commitment(&policy, &[object], &Actor(actor.clone()))
            .unwrap();
        let PolicyCmdResult::CommitRegistrations {
            registrations_commitment,
        } = execute(
            &mut module,
            &actor,
            &policy,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
            10,
        )
        .unwrap()
        else {
            panic!("expected commitment")
        };
        let reveal = PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        };
        let before = module.store.serialize();
        assert!(matches!(
            execute(&mut module, &actor, &policy, reveal.clone(), 611),
            Err(AcpError::CommitmentExpired { .. })
        ));
        assert_eq!(module.store.serialize(), before);
        execute(&mut module, &actor, &policy, reveal, 610).unwrap();
    }
}

#[test]
fn corrupt_policy_and_relationship_records_cannot_authorize_or_be_overwritten() {
    let (mut module, first, second, policy, object) = setup();
    module
        .direct_policy_cmd(&second, &policy, PolicyCmd::RegisterObject(object))
        .unwrap();
    let grant = Relationship::with_entity("file", "report", "reader", first.clone());
    let policy_key = keys::policy_key(&policy);
    let policy_bytes = module.store.get(&policy_key).unwrap();
    for invalid in [b"{".to_vec(), {
        let mut record: PolicyRecord = serde_json::from_slice(&policy_bytes).unwrap();
        record.policy.id = "other".into();
        serde_json::to_vec(&record).unwrap()
    }] {
        module.store.put(&policy_key, invalid);
        let before = module.store.serialize();
        assert!(matches!(
            module.query_policy(&policy),
            Err(AcpError::State(_))
        ));
        assert!(matches!(
            module.edit_policy(&first, &policy, "", PolicyMarshalingType::ShortYaml),
            Err(AcpError::State(_))
        ));
        assert!(matches!(
            module.direct_policy_cmd(&second, &policy, PolicyCmd::SetRelationship(grant.clone())),
            Err(AcpError::State(_))
        ));
        assert_eq!(module.store.serialize(), before);
    }
    module.store.put(&policy_key, policy_bytes);
    let owner = Relationship::with_entity("file", "report", "owner", second.clone());
    let relations = module.query_policy(&policy).unwrap().relations;
    let owner_key = keys::relationship_generation_key(
        &policy,
        relations.pair(&owner).unwrap(),
        &keys::relationship_storage_key(&owner),
    );
    let owner_bytes = module.store.get(&owner_key).unwrap();
    module.store.put(&owner_key, b"{".to_vec());
    let before = module.store.serialize();
    assert!(matches!(
        module.direct_policy_cmd(&second, &policy, PolicyCmd::SetRelationship(grant.clone())),
        Err(AcpError::State(_))
    ));
    assert_eq!(module.store.serialize(), before);
    module.store.put(&owner_key, owner_bytes.clone());
    let grant_key = keys::relationship_generation_key(
        &policy,
        relations.pair(&grant).unwrap(),
        &keys::relationship_storage_key(&grant),
    );
    for invalid in [b"{".to_vec(), owner_bytes] {
        module.store.put(&grant_key, invalid);
        let before = module.store.serialize();
        for command in [
            PolicyCmd::SetRelationship(grant.clone()),
            PolicyCmd::DeleteRelationship(grant.clone()),
        ] {
            assert!(matches!(
                module.direct_policy_cmd(&second, &policy, command),
                Err(AcpError::State(_))
            ));
            assert_eq!(module.store.serialize(), before);
        }
    }
}

#[test]
fn fresh_reveal_has_no_amendment_event() {
    let (mut module, actor, _, policy, object) = setup();
    let generated = module
        .query_generate_commitment(
            &policy,
            std::slice::from_ref(&object),
            &Actor(actor.clone()),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = execute(
        &mut module,
        &actor,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        10,
    )
    .unwrap()
    else {
        panic!("expected commitment");
    };
    let result = execute(
        &mut module,
        &actor,
        &policy,
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        },
        20,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&result).unwrap()["RevealRegistration"]
            .as_object()
            .unwrap()
            .get("event"),
        Some(&serde_json::Value::Null)
    );
    let PolicyCmdResult::RevealRegistration {
        record,
        event: None,
    } = result
    else {
        panic!("fresh registration must not produce an amendment");
    };
    assert_eq!(record.metadata.creation_ts.block_height, 10);
    assert_eq!(record.metadata.tx_hash, vec![20; 32]);
    assert!(
        module
            .store
            .prefix_iter(keys::AMENDMENT_EVENT_PREFIX)
            .next()
            .is_none()
    );
    let recovered =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    assert!(recovered.query_object_owner(&policy, &object).unwrap().0);
}

#[test]
fn empty_object_commands_fail_without_effects_and_opaque_ids_roundtrip() {
    let (mut module, actor, _, policy, mut object) = setup();
    object.id.clear();
    let relation = Relationship::with_entity("file", "", "reader", actor.clone());
    let commands = [
        PolicyCmd::RegisterObject(object.clone()),
        PolicyCmd::ArchiveObject(object.clone()),
        PolicyCmd::UnarchiveObject(object.clone()),
        PolicyCmd::SetRelationship(relation.clone()),
        PolicyCmd::DeleteRelationship(relation),
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: 1,
            proof: RegistrationProof {
                object: object.clone(),
                merkle_proof: vec![],
                leaf_count: 1,
                leaf_index: 0,
            },
        },
    ];
    for restored in [false, true] {
        if restored {
            module = AcpModule::from_store(
                InMemoryKvStore::deserialize(&module.store.serialize()).unwrap(),
            );
        }
        let before = module.store.serialize();
        for command in &commands {
            assert!(matches!(
                module.direct_policy_cmd(&actor, &policy, command.clone()),
                Err(AcpError::InvalidAccessRequest { .. })
            ));
            assert_eq!(module.store.serialize(), before);
        }
        assert!(
            AcpModule::generate_registration_commitment(
                &policy,
                std::slice::from_ref(&object),
                &Actor(actor.clone())
            )
            .is_err()
        );
    }
    for id in [" ", "folder/report", "報告", "*"] {
        object.id = id.into();
        let PolicyCmdResult::RegisterObject { record } = module
            .direct_policy_cmd(&actor, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap()
        else {
            panic!("expected registration");
        };
        assert_eq!(record.relationship.object_id, id);
        let generated = AcpModule::generate_registration_commitment(
            &policy,
            std::slice::from_ref(&object),
            &Actor(actor.clone()),
        )
        .unwrap();
        assert_eq!(generated.proofs[0].object.id, id);
    }
}
