use super::*;

const POLICY: &str = "name: incarnation\nresources:\n  - name: file\n    relations:\n      - name: reader\n  - name: group\n    relations:\n      - name: member\n";
const NO_READER: &str = "name: incarnation\nresources:\n  - name: file\n  - name: group\n    relations:\n      - name: member\n";

fn fixture(count: usize) -> (AcpModule, Did, String, Object, Vec<RelationshipRecord>) {
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
    let definition = module.query_policy(&policy).unwrap();
    let mut records = Vec::new();
    for index in 0..count {
        let relationship = Relationship::with_entity(
            "file",
            "report",
            "reader",
            Did::new(format!("did:key:reader-{index:04}")).unwrap(),
        );
        let row = RelationshipRecord {
            incarnation: 0,
            generations: definition.relations.pair(&relationship).unwrap(),
            policy_id: policy.clone(),
            relationship,
            archived: false,
            supplied_metadata: Default::default(),
            metadata: definition.metadata.clone(),
        };
        relationship_mutations::put(&mut module.store, &row).unwrap();
        records.push(row);
    }
    (module, owner, policy, object, records)
}

fn primary(row: &RelationshipRecord) -> Vec<u8> {
    keys::relationship_generation_key(
        &row.policy_id,
        row.generations,
        &keys::relationship_storage_key(&row.relationship, row.incarnation),
    )
}

fn archive(
    module: &mut AcpModule,
    owner: &Did,
    policy: &str,
    object: &Object,
    budget: &CommandBudget,
) -> u64 {
    let PolicyCmdResult::ArchiveObject {
        found: true,
        relationships_removed,
    } = module
        .direct_policy_cmd_with_budget(
            owner,
            policy,
            PolicyCmd::ArchiveObject(object.clone()),
            budget,
        )
        .unwrap()
    else {
        panic!("expected archive")
    };
    relationships_removed
}

fn restore(module: &AcpModule) -> AcpModule {
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    restored.validate_restored_state().unwrap();
    restored
}

#[test]
fn archive_cost_is_independent_of_grant_rows_and_late_exhaustion_is_atomic() {
    let mut costs = Vec::new();
    for count in [32, 2048] {
        let (mut module, owner, policy, object, rows) = fixture(count);
        let original = module.clone();
        let budget = CommandBudget::new(u64::MAX);
        assert_eq!(
            archive(&mut module, &owner, &policy, &object, &budget),
            count as u64 + 1
        );
        costs.push(budget.consumed());
        assert!(rows.iter().all(|row| module.store.has(&primary(row))));
        assert_eq!(
            relationship_index::read_logical_count(&module.store, &policy, rows[0].generations)
                .unwrap(),
            0
        );
        assert_eq!(
            object_state::read(&module.store, &policy, &object.resource, &object.id).unwrap(),
            1
        );
        restore(&module);
        let mut exact = original.clone();
        assert_eq!(
            archive(
                &mut exact,
                &owner,
                &policy,
                &object,
                &CommandBudget::new(budget.consumed())
            ),
            count as u64 + 1
        );
        assert_eq!(exact.store.serialize(), module.store.serialize());
        let mut short = original.clone();
        let allowance = CommandBudget::new(budget.consumed() - 1);
        assert!(matches!(
            short.direct_policy_cmd_with_budget(
                &owner,
                &policy,
                PolicyCmd::ArchiveObject(object),
                &allowance
            ),
            Err(AcpError::CommandBudgetExceeded)
        ));
        assert!(allowance.is_exhausted());
        assert_eq!(short.store.serialize(), original.store.serialize());
    }
    assert_eq!(costs[0], costs[1]);
}

#[test]
fn old_cleanup_and_restart_preserve_regrants_and_never_double_count_edits() {
    let (mut module, owner, policy, object, rows) = fixture(130);
    assert_eq!(
        archive(
            &mut module,
            &owner,
            &policy,
            &object,
            &CommandBudget::new(u64::MAX)
        ),
        131
    );
    assert_eq!(
        archive(
            &mut module,
            &owner,
            &policy,
            &object,
            &CommandBudget::new(u64::MAX)
        ),
        0
    );
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::UnarchiveObject(object.clone()))
        .unwrap();
    assert!(
        module
            .get_relationship(&policy, &rows[0].relationship)
            .unwrap()
            .is_none()
    );
    let PolicyCmdResult::SetRelationship { record: fresh, .. } = module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::SetRelationship(rows[0].relationship.clone()),
        )
        .unwrap()
    else {
        panic!("grant")
    };
    assert_eq!(fresh.incarnation, 1);
    assert_ne!(primary(&fresh), primary(&rows[0]));
    let mut module = restore(&module);
    module.end_blocker(&BlockExecCtx::default()).unwrap();
    assert!(module.store.has(&primary(&fresh)));
    let old_remaining = rows
        .iter()
        .filter(|row| module.store.has(&primary(row)))
        .count();
    assert!(old_remaining > 0 && old_remaining < rows.len());
    let mut module = restore(&module);
    assert_eq!(
        module
            .edit_policy(&owner, &policy, NO_READER, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .0,
        1
    );
    module
        .edit_policy(&owner, &policy, POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap();
    let PolicyCmdResult::SetRelationship { record: newest, .. } = module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::SetRelationship(rows[0].relationship.clone()),
        )
        .unwrap()
    else {
        panic!("grant")
    };
    for height in 1..=4 {
        module
            .end_blocker(&BlockExecCtx {
                timestamp: Timestamp {
                    block_height: height,
                    seconds: height,
                },
                ..Default::default()
            })
            .unwrap();
        module = restore(&module);
    }
    assert!(rows.iter().all(|row| !module.store.has(&primary(row))));
    assert!(!module.store.has(&primary(&fresh)));
    assert!(module.store.has(&primary(&newest)));
    assert_eq!(
        archive(
            &mut module,
            &owner,
            &policy,
            &object,
            &CommandBudget::new(u64::MAX)
        ),
        2
    );
}

#[test]
fn obsolete_primary_corruption_is_rejected_by_restore_and_atomic_cleanup() {
    let (mut module, owner, policy, object, rows) = fixture(2);
    module.store.put(&primary(&rows[1]), b"{".to_vec());
    assert_eq!(
        archive(
            &mut module,
            &owner,
            &policy,
            &object,
            &CommandBudget::new(u64::MAX)
        ),
        3
    );
    assert!(module.validate_restored_state().is_err());
    let before = module.store.serialize();
    assert!(module.end_blocker(&BlockExecCtx::default()).is_err());
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn invalid_incarnation_and_cleanup_metadata_fail_closed() {
    let (module, owner, policy, object, _) = fixture(2);
    for value in [
        vec![0],
        0u64.to_be_bytes().to_vec(),
        u64::MAX.to_be_bytes().to_vec(),
    ] {
        let mut broken = module.clone();
        broken.store.put(
            &object_state::key(&policy, &object.resource, &object.id),
            value,
        );
        let before = broken.store.serialize();
        assert!(
            broken
                .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(object.clone()))
                .is_err()
        );
        assert_eq!(broken.store.serialize(), before);
    }
    let mut archived = module;
    archive(
        &mut archived,
        &owner,
        &policy,
        &object,
        &CommandBudget::new(u64::MAX),
    );
    let marker = marker_key(&policy, &object, 0);
    for corruption in 0..4 {
        let mut broken = archived.clone();
        let bytes = broken.store.get(&marker).unwrap();
        let job = decode(&bytes).unwrap();
        match corruption {
            0 => broken.store.delete(&marker),
            1 => broken.store.delete(&queue_key(job.sequence)),
            2 => broken.store.put(COUNTER_KEY, 0u64.to_be_bytes().to_vec()),
            3 => broken.store.put(&marker, b"{}".to_vec()),
            _ => unreachable!(),
        }
        assert!(broken.validate_restored_state().is_err());
        if corruption != 1 {
            let before = broken.store.serialize();
            assert!(broken.end_blocker(&BlockExecCtx::default()).is_err());
            assert_eq!(broken.store.serialize(), before);
        }
    }
}

#[test]
fn policy_retirement_drains_old_jobs_before_incarnation_state() {
    let (mut module, owner, policy, object, _) = fixture(130);
    archive(
        &mut module,
        &owner,
        &policy,
        &object,
        &CommandBudget::new(u64::MAX),
    );
    module.delete_policy(&owner, &policy).unwrap();
    for height in 0..=4 {
        module
            .end_blocker(&BlockExecCtx {
                timestamp: Timestamp {
                    block_height: height,
                    seconds: height,
                },
                ..Default::default()
            })
            .unwrap();
        module = restore(&module);
    }
    assert!(!module.policy_cleanup_pending(&policy).unwrap());
    assert!(
        module
            .store
            .prefix_iter(&object_state::policy_prefix(&policy))
            .next()
            .is_none()
    );
    assert!(
        module
            .store
            .prefix_iter(&marker_prefix(&policy))
            .next()
            .is_none()
    );
    assert!(module.store.prefix_iter(QUEUE_PREFIX).next().is_none());
}

#[test]
fn transfers_and_commitment_amendments_preserve_current_grants_and_incarnation() {
    let (mut module, owner, policy, object, rows) = fixture(1);
    archive(
        &mut module,
        &owner,
        &policy,
        &object,
        &CommandBudget::new(u64::MAX),
    );
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::UnarchiveObject(object.clone()))
        .unwrap();
    let PolicyCmdResult::SetRelationship { record: fresh, .. } = module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::SetRelationship(rows[0].relationship.clone()),
        )
        .unwrap()
    else {
        panic!("grant")
    };
    let next = Did::new("did:key:next").unwrap();
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::TransferObject {
                object: object.clone(),
                new_owner: Actor(next),
            },
        )
        .unwrap();
    let amended = Did::new("did:key:amended").unwrap();
    let generated = AcpModule::generate_registration_commitment(
        &policy,
        std::slice::from_ref(&object),
        &Actor(amended.clone()),
    )
    .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = module
        .direct_policy_cmd(
            &amended,
            &policy,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
        )
        .unwrap()
    else {
        panic!("commit")
    };
    let registration = module
        .registration_owner_record(&policy, &object)
        .unwrap()
        .unwrap();
    assert!(
        registrations_commitment.metadata.creation_ts.block_height
            <= registration.metadata.creation_ts.block_height
    );
    assert!(matches!(
        module
            .direct_policy_cmd(
                &amended,
                &policy,
                PolicyCmd::RevealRegistration {
                    registrations_commitment_id: registrations_commitment.id,
                    proof: generated.proofs[0].clone()
                }
            )
            .unwrap(),
        PolicyCmdResult::RevealRegistration { event: Some(_), .. }
    ));
    assert_eq!(
        object_state::read(&module.store, &policy, &object.resource, &object.id).unwrap(),
        1
    );
    assert_eq!(
        module
            .get_relationship(&policy, &fresh.relationship)
            .unwrap()
            .unwrap()
            .incarnation,
        1
    );
    assert_eq!(
        module
            .query_object_owner(&policy, &object)
            .unwrap()
            .1
            .unwrap()
            .metadata
            .owner_did,
        amended.to_string()
    );
    module.end_blocker(&BlockExecCtx::default()).unwrap();
    assert!(module.store.has(&primary(&fresh)));
    restore(&module);
}

#[test]
fn maximum_records_progress_and_byte_exhaustion_does_not_starve_the_next_object() {
    let (mut module, owner, policy, first, rows) = fixture(3);
    let second = Object {
        resource: "file".into(),
        id: "second".into(),
    };
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(second.clone()))
        .unwrap();
    let mut all = rows.clone();
    for row in &rows {
        let mut other = row.clone();
        other.relationship.object_id = second.id.clone();
        relationship_mutations::put(&mut module.store, &other).unwrap();
        all.push(other);
    }
    for row in &all {
        let key = primary(row);
        let mut bytes = module.store.get(&key).unwrap();
        bytes.resize(crate::kv_store::NATIVE_MAX_VALUE_BYTES, b' ');
        module.store.put(&key, bytes);
    }
    archive(
        &mut module,
        &owner,
        &policy,
        &first,
        &CommandBudget::new(u64::MAX),
    );
    archive(
        &mut module,
        &owner,
        &policy,
        &second,
        &CommandBudget::new(u64::MAX),
    );
    module.end_blocker(&BlockExecCtx::default()).unwrap();
    assert!(rows.iter().all(|row| !module.store.has(&primary(row))));
    assert!(all[3..].iter().any(|row| module.store.has(&primary(row))));
    restore(&module);
    module.end_blocker(&BlockExecCtx::default()).unwrap();
    assert!(all.iter().all(|row| !module.store.has(&primary(row))));
    restore(&module);
}
