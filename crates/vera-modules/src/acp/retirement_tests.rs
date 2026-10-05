use super::super::retirement_cleanup::{JOB_ITEMS, MAX_BYTES, MAX_ITEMS};
use super::*;

const POLICY: &str = "name: retirement\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n";

fn actor(name: &str) -> Did {
    Did::new(format!("did:key:{name}")).unwrap()
}

fn block(height: u64) -> BlockExecCtx {
    BlockExecCtx {
        timestamp: Timestamp {
            seconds: height * 10,
            block_height: height,
        },
        ..Default::default()
    }
}

fn policy(module: &mut AcpModule) -> String {
    module
        .create_policy(&actor("creator"), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id
}

fn object(id: &str) -> Object {
    Object {
        resource: "file".into(),
        id: id.into(),
    }
}

fn command(
    module: &mut AcpModule,
    policy: &str,
    signer: &str,
    command: PolicyCmd,
    height: u64,
) -> PolicyCmdResult {
    module
        .execute_policy_cmd(
            &actor(signer),
            policy,
            command,
            &block(height),
            &TxExecCtx {
                signer: actor(signer).to_string(),
                tx_hash: vec![1; 32],
                sequence: 0,
            },
        )
        .unwrap()
}

fn register(module: &mut AcpModule, policy: &str, id: &str) {
    command(
        module,
        policy,
        "owner",
        PolicyCmd::RegisterObject(object(id)),
        1,
    );
}

fn registration(
    module: &mut AcpModule,
    policy: &str,
    id: &str,
    height: u64,
) -> (RegistrationsCommitment, AmendmentEvent) {
    let object = object(id);
    let generated = module
        .query_generate_commitment(
            policy,
            std::slice::from_ref(&object),
            &Actor(actor("claimant")),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = command(
        module,
        policy,
        "claimant",
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        height,
    )
    else {
        panic!("expected commitment");
    };
    command(
        module,
        policy,
        "owner",
        PolicyCmd::RegisterObject(object),
        height + 1,
    );
    let PolicyCmdResult::RevealRegistration {
        event: Some(event), ..
    } = command(
        module,
        policy,
        "claimant",
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        },
        height + 2,
    )
    else {
        panic!("expected ownership amendment");
    };
    let PolicyCmdResult::FlagHijackAttempt { event } = command(
        module,
        policy,
        "claimant",
        PolicyCmd::FlagHijackAttempt { event_id: event.id },
        height + 3,
    ) else {
        panic!("expected hijack flag");
    };
    (registrations_commitment, event)
}

fn restore(module: &AcpModule) -> AcpModule {
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    restored.validate_restored_state().unwrap();
    restored
}

fn remaining_relationships(module: &AcpModule, policy: &str) -> usize {
    module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(policy))
        .count()
}

fn finish(module: &mut AcpModule, policy: &str) {
    for height in 70..170 {
        if !module.policy_cleanup_pending(policy).unwrap() {
            return;
        }
        module.end_blocker(&block(height)).unwrap();
        *module = restore(module);
    }
    panic!("policy cleanup did not finish");
}

fn commitment_keys(record: &RegistrationsCommitment) -> Vec<Vec<u8>> {
    vec![
        keys::commitment_key(record.id),
        keys::commitment_policy_index_key(&record.policy_id, record.id),
        keys::commitment_by_commitment_index_key(&record.commitment, record.id),
        AcpModule::commitment_expiry_key(record),
    ]
}

#[test]
fn retirement_hides_records_immediately_and_repeated_delete_does_not_enqueue_again() {
    let mut module = AcpModule::new();
    let id = policy(&mut module);
    let (commitment, amendment) = registration(&mut module, &id, "claimed", 2);
    register(&mut module, &id, "archived");
    command(
        &mut module,
        &id,
        "owner",
        PolicyCmd::ArchiveObject(object("archived")),
        6,
    );
    assert_eq!(
        module.query_hijack_attempts_by_policy(&id).unwrap().len(),
        1
    );
    let count = remaining_relationships(&module, &id);
    assert!(module.delete_policy(&actor("creator"), &id).unwrap());
    assert!(!module.store.has(&keys::policy_key(&id)));
    assert!(!module.zanzibar_policies.contains_key(&id));
    assert_eq!(remaining_relationships(&module, &id), count);
    assert!(module.store.has(&keys::commitment_key(commitment.id)));
    assert!(module.store.has(&keys::amendment_event_key(amendment.id)));
    let retired: RetiredPolicy =
        borsh::from_slice(module.store.get_ref(&retired_key(&id)).unwrap()).unwrap();
    assert!(matches!(retired.phase, Phase::Relationships));
    assert!(module.store.has(&queue_key(retired.sequence)));
    assert!(matches!(
        module.query_policy(&id),
        Err(AcpError::PolicyNotFound { .. })
    ));
    for object in [object("claimed"), object("archived")] {
        let (found, record) = module.query_object_owner(&id, &object).unwrap();
        assert!(!found);
        assert!(record.is_none());
    }
    assert!(matches!(
        module.query_registrations_commitment(commitment.id),
        Err(AcpError::CommitmentNotFound { .. })
    ));
    assert!(
        module
            .query_registrations_commitment_by_commitment(&commitment.commitment)
            .unwrap()
            .is_empty()
    );
    assert!(
        module
            .get_amendment_event_by_id(amendment.id)
            .unwrap()
            .is_none()
    );
    assert!(
        module
            .query_hijack_attempts_by_policy(&id)
            .unwrap()
            .is_empty()
    );
    // Cleanup still needs the retained record even though public reads hide it.
    assert!(
        module
            .get_commitment_by_id(commitment.id)
            .unwrap()
            .is_some()
    );
    let before = module.store.serialize();
    assert!(!module.delete_policy(&actor("creator"), &id).unwrap());
    assert_eq!(module.store.serialize(), before);
    let restored = restore(&module);
    assert!(
        !restored
            .query_object_owner(&id, &object("claimed"))
            .unwrap()
            .0
    );
    assert!(
        restored
            .query_registrations_commitment(commitment.id)
            .is_err()
    );
}

#[test]
fn pending_cleanup_survives_restore_and_removes_expired_and_active_record_indexes() {
    let mut module = AcpModule::new();
    let id = policy(&mut module);
    let (expired, old_event) = registration(&mut module, &id, "expired", 2);
    module.end_blocker(&block(63)).unwrap();
    assert!(
        module
            .query_registrations_commitment(expired.id)
            .unwrap()
            .expired
    );
    let (active, event) = registration(&mut module, &id, "active", 64);
    let other = policy(&mut module);
    let (retained, retained_event) = registration(&mut module, &other, "retained", 64);
    let other_relationships = module
        .store
        .prefix_scan(&keys::relationship_policy_prefix(&other));
    module.delete_policy(&actor("creator"), &id).unwrap();
    module = restore(&module);
    finish(&mut module, &id);
    assert_eq!(remaining_relationships(&module, &id), 0);
    assert!(!module.store.has(&retired_key(&id)));
    assert_eq!(module.store.prefix_iter(QUEUE_PREFIX).count(), 0);
    for record in [&expired, &active] {
        for key in commitment_keys(record) {
            assert!(!module.store.has(&key), "retained commitment key: {key:?}");
        }
    }
    for event in [&old_event, &event] {
        for key in [
            keys::amendment_event_key(event.id),
            keys::amendment_event_policy_index_key(&id, event.id),
        ] {
            assert!(!module.store.has(&key), "retained amendment key: {key:?}");
        }
    }
    assert_eq!(
        module
            .store
            .prefix_scan(&keys::relationship_policy_prefix(&other)),
        other_relationships
    );
    assert_eq!(
        module.query_registrations_commitment(retained.id).unwrap(),
        retained
    );
    assert_eq!(
        module.get_amendment_event_by_id(retained_event.id).unwrap(),
        Some(retained_event)
    );
    assert!(module.query_policy(&other).is_ok());
    module.validate_restored_state().unwrap();
}

#[test]
fn recreating_the_same_definition_cannot_resurrect_or_clean_the_new_policys_records() {
    let mut module = AcpModule::new();
    let old = policy(&mut module);
    register(&mut module, &old, "report");
    module.delete_policy(&actor("creator"), &old).unwrap();
    let new = policy(&mut module);
    assert_ne!(old, new);
    assert!(
        !module
            .query_object_owner(&new, &object("report"))
            .unwrap()
            .0
    );
    register(&mut module, &new, "report");
    let new_records = module
        .store
        .prefix_scan(&keys::relationship_policy_prefix(&new));
    finish(&mut module, &old);
    assert!(
        !module
            .query_object_owner(&old, &object("report"))
            .unwrap()
            .0
    );
    assert!(
        module
            .query_object_owner(&new, &object("report"))
            .unwrap()
            .0
    );
    assert_eq!(
        module
            .store
            .prefix_scan(&keys::relationship_policy_prefix(&new)),
        new_records
    );
}

#[test]
fn cleanup_shares_the_block_budget_fairly_and_resumes_after_restore() {
    let mut module = AcpModule::new();
    let first = policy(&mut module);
    let second = policy(&mut module);
    let total = MAX_ITEMS * 2 + 1;
    for id in [&first, &second] {
        for index in 0..total {
            register(&mut module, id, &format!("record-{index}"));
        }
        module.delete_policy(&actor("creator"), id).unwrap();
    }
    for height in [2, 3] {
        let before = [
            remaining_relationships(&module, &first),
            remaining_relationships(&module, &second),
        ];
        module.end_blocker(&block(height)).unwrap();
        let removed = [
            before[0] - remaining_relationships(&module, &first),
            before[1] - remaining_relationships(&module, &second),
        ];
        assert!(removed.iter().all(|count| *count > 0));
        assert!(removed.iter().sum::<usize>() <= MAX_ITEMS);
        assert!(removed[0].abs_diff(removed[1]) <= JOB_ITEMS);
        assert!(module.policy_cleanup_pending(&first).unwrap());
        assert!(module.policy_cleanup_pending(&second).unwrap());
        module = restore(&module);
    }
    finish(&mut module, &first);
    finish(&mut module, &second);
    assert_eq!(module.store.prefix_iter(QUEUE_PREFIX).count(), 0);
}

#[test]
fn byte_exhaustion_preserves_the_next_policys_turn_across_blocks() {
    let mut module = AcpModule::new();
    let first = policy(&mut module);
    let second = policy(&mut module);
    for (id, count) in [(&first, 8), (&second, 1)] {
        for index in 0..count {
            register(&mut module, id, &format!("record-{index}"));
        }
        let prefix = keys::relationship_policy_prefix(id);
        let records: Vec<_> = module
            .store
            .prefix_iter(&prefix)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        for (key, mut value) in records {
            value.resize(1 << 20, b' ');
            module.store.put(&key, value);
        }
        module.delete_policy(&actor("creator"), id).unwrap();
    }
    module.end_blocker(&block(2)).unwrap();
    assert_eq!(remaining_relationships(&module, &first), 5);
    assert_eq!(remaining_relationships(&module, &second), 1);
    module = restore(&module);
    module.end_blocker(&block(3)).unwrap();
    assert_eq!(
        remaining_relationships(&module, &second),
        0,
        "an exhausted byte budget must not cycle queued jobs back behind the same head"
    );
    assert!(!module.policy_cleanup_pending(&second).unwrap());
    assert!(module.policy_cleanup_pending(&first).unwrap());
}

#[test]
fn a_job_that_cannot_fit_any_record_keeps_the_first_turn_in_the_next_block() {
    let mut module = AcpModule::new();
    let first = policy(&mut module);
    let second = policy(&mut module);
    for id in [&first, &second] {
        for index in 0..17 {
            register(&mut module, id, &format!("record-{index}"));
        }
        let prefix = keys::relationship_policy_prefix(id);
        let records: Vec<_> = module
            .store
            .prefix_iter(&prefix)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        for (key, mut value) in records {
            value.resize(250 << 10, b' ');
            module.store.put(&key, value);
        }
        module.delete_policy(&actor("creator"), id).unwrap();
    }
    module.end_blocker(&block(2)).unwrap();
    assert_eq!(remaining_relationships(&module, &first), 1);
    assert_eq!(remaining_relationships(&module, &second), 17);
    module = restore(&module);
    module.end_blocker(&block(3)).unwrap();
    assert_eq!(
        remaining_relationships(&module, &second),
        1,
        "a zero-progress job must keep its position for the next block's full budget"
    );
    assert_eq!(remaining_relationships(&module, &first), 1);
    assert!(module.policy_cleanup_pending(&first).unwrap());
    assert!(module.policy_cleanup_pending(&second).unwrap());
}

#[test]
fn malformed_counter_and_next_sequence_collision_reject_deletion_without_mutation() {
    for counter in [vec![1], 0u64.to_be_bytes().to_vec()] {
        let mut module = AcpModule::new();
        let first = policy(&mut module);
        let second = policy(&mut module);
        module.delete_policy(&actor("creator"), &first).unwrap();
        // Resetting to zero makes the proposed next sequence collide with the first job.
        module.store.put(COUNTER_KEY, counter);
        let before = module.store.serialize();
        assert!(module.delete_policy(&actor("creator"), &second).is_err());
        assert_eq!(module.store.serialize(), before);
        assert!(module.query_policy(&second).is_ok());
    }
}

#[test]
fn maximum_native_records_make_bounded_progress_across_cleanup_ticks() {
    let mut module = AcpModule::new();
    let id = policy(&mut module);
    let empty = Relationship::with_entity("file", "", "owner", actor("owner"));
    let key_overhead =
        keys::relationship_key(&id, &keys::relationship_storage_key(&empty, 0)).len();
    let object_bytes = ((64 << 10) - key_overhead) / 2;
    let padding = "x".repeat(object_bytes - 2);
    for index in 0..7 {
        register(&mut module, &id, &format!("{index:02}{padding}"));
    }
    let prefix = keys::relationship_policy_prefix(&id);
    let records: Vec<_> = module
        .store
        .prefix_iter(&prefix)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    for (key, mut value) in records {
        assert!(key.len() <= 64 << 10);
        assert!(key.len() >= (64 << 10) - 1);
        // Trailing JSON whitespace keeps the relationship valid at the native value bound.
        value.resize(1 << 20, b' ');
        module.store.put(&key, value);
    }
    module.delete_policy(&actor("creator"), &id).unwrap();
    module = restore(&module);
    for height in 10..20 {
        if !module.policy_cleanup_pending(&id).unwrap() {
            break;
        }
        let before = remaining_relationships(&module, &id);
        module.end_blocker(&block(height)).unwrap();
        let removed = before - remaining_relationships(&module, &id);
        if before > 0 {
            assert!(
                removed > 0,
                "a valid maximum-size record must make progress"
            );
        }
        assert!(removed * (1 << 20) < MAX_BYTES);
        module = restore(&module);
    }
    assert!(!module.policy_cleanup_pending(&id).unwrap());
    assert_eq!(remaining_relationships(&module, &id), 0);
}

#[test]
fn corrupt_later_job_rolls_back_earlier_cleanup_in_the_same_block() {
    let mut module = AcpModule::new();
    let first = policy(&mut module);
    let second = policy(&mut module);
    for id in [&first, &second] {
        for index in 0..MAX_ITEMS + 1 {
            register(&mut module, id, &format!("record-{index}"));
        }
        module.delete_policy(&actor("creator"), id).unwrap();
    }
    let active = policy(&mut module);
    let (commitment, _) = registration(&mut module, &active, "due-to-expire", 2);
    let marker: RetiredPolicy =
        borsh::from_slice(module.store.get_ref(&retired_key(&second)).unwrap()).unwrap();
    module.store.put(&queue_key(marker.sequence), vec![255]);
    assert!(module.validate_restored_state().is_err());
    let before = module.store.serialize();
    assert!(module.end_blocker(&block(70)).is_err());
    assert!(
        !module
            .query_registrations_commitment(commitment.id)
            .unwrap()
            .expired
    );
    assert_eq!(module.store.serialize(), before);
    assert_eq!(remaining_relationships(&module, &first), MAX_ITEMS + 1);
    assert_eq!(remaining_relationships(&module, &second), MAX_ITEMS + 1);
}

#[test]
fn corrupt_commitment_secondary_indexes_roll_back_the_entire_cleanup_tick() {
    let mut module = AcpModule::new();
    let id = policy(&mut module);
    registration(&mut module, &id, "earlier", 2);
    let (record, _) = registration(&mut module, &id, "later", 2);
    for key in [
        keys::commitment_by_commitment_index_key(&record.commitment, record.id),
        AcpModule::commitment_expiry_key(&record),
    ] {
        for value in [None, Some(vec![1])] {
            let mut candidate = module.clone();
            if let Some(value) = value {
                candidate.store.put(&key, value);
            } else {
                candidate.store.delete(&key);
            }
            candidate.delete_policy(&actor("creator"), &id).unwrap();
            let mut rejected = false;
            for height in 10..20 {
                let before = candidate.store.serialize();
                if candidate.end_blocker(&block(height)).is_err() {
                    assert_eq!(candidate.store.serialize(), before);
                    rejected = true;
                    break;
                }
            }
            assert!(rejected, "cleanup accepted corrupt index {key:?}");
            assert!(candidate.store.has(&keys::commitment_key(record.id)));
            assert!(candidate.query_policy(&id).is_err());
        }
    }
}

#[test]
fn restoration_rejects_retirement_phase_queue_and_counter_inconsistencies() {
    let mut module = AcpModule::new();
    let id = policy(&mut module);
    let (commitment, _) = registration(&mut module, &id, "retained", 2);
    module.delete_policy(&actor("creator"), &id).unwrap();
    module.validate_restored_state().unwrap();
    let marker: RetiredPolicy =
        borsh::from_slice(module.store.get_ref(&retired_key(&id)).unwrap()).unwrap();

    for case in 0..5 {
        let mut candidate = module.clone();
        match case {
            0 | 1 => {
                let mut advanced = marker.clone();
                advanced.phase = if case == 0 {
                    Phase::Commitments
                } else {
                    // Isolate a skipped commitment phase from leftover relationship rows.
                    let prefix = keys::relationship_policy_prefix(&id);
                    let keys: Vec<_> = candidate
                        .store
                        .prefix_iter(&prefix)
                        .map(|(key, _)| key.to_vec())
                        .collect();
                    for key in keys {
                        candidate.store.delete(&key);
                    }
                    assert!(candidate.store.has(&keys::commitment_key(commitment.id)));
                    Phase::Amendments
                };
                candidate
                    .store
                    .put(&retired_key(&id), borsh::to_vec(&advanced).unwrap());
            }
            2 => candidate.store.delete(&queue_key(marker.sequence)),
            3 => candidate
                .store
                .put(&queue_key(marker.sequence), vec![b'f'; 64]),
            4 => candidate
                .store
                .put(COUNTER_KEY, (marker.sequence - 1).to_be_bytes().to_vec()),
            _ => unreachable!(),
        }
        let mut restored = AcpModule::from_store(
            InMemoryKvStore::deserialize(&candidate.store.serialize()).unwrap(),
        );
        let before = restored.store.serialize();
        assert!(restored.validate_restored_state().is_err(), "case {case}");
        assert_eq!(restored.store.serialize(), before);
        if case == 4 {
            // Expiry runs before cleanup; the rejected counter must roll that back too.
            assert!(restored.end_blocker(&block(70)).is_err());
            assert_eq!(restored.store.serialize(), before);
            assert!(
                !restored
                    .get_commitment_by_id(commitment.id)
                    .unwrap()
                    .unwrap()
                    .expired
            );
        }
    }
}

#[test]
fn restore_rejects_legacy_relationship_namespaces_even_beside_current_records() {
    let mut module = AcpModule::new();
    let id = policy(&mut module);
    register(&mut module, &id, "report");
    assert_eq!(keys::RELATIONSHIP_PREFIX, b"relationship/v5/");
    let (key, value) = module
        .store
        .prefix_iter(&keys::relationship_policy_prefix(&id))
        .next()
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .unwrap();
    let suffix = key.strip_prefix(keys::RELATIONSHIP_PREFIX).unwrap();
    for legacy in [
        b"relationship/".as_slice(),
        b"relationship/v2/".as_slice(),
        b"relationship/v3/".as_slice(),
        b"relationship/v4/".as_slice(),
    ] {
        let mut candidate = module.clone();
        candidate
            .store
            .put(&[legacy, suffix].concat(), value.clone());
        let restored = AcpModule::from_store(candidate.store.clone());
        let before = restored.store.serialize();
        assert!(restored.validate_restored_state().is_err());
        assert_eq!(restored.store.serialize(), before);
    }
}

#[test]
fn retired_snapshot_rejects_duplicate_or_unsorted_generation_names() {
    let mut module = AcpModule::new();
    let id = policy(&mut module);
    register(&mut module, &id, "report");
    module.delete_policy(&actor("creator"), &id).unwrap();
    module.validate_restored_state().unwrap();
    let retired = module.retired_policy(&id).unwrap().unwrap();
    let entries: Vec<_> = retired
        .relations
        .active
        .iter()
        .map(|(resource, relations)| {
            (
                resource.clone(),
                relations
                    .iter()
                    .map(|(name, generation)| (name.clone(), *generation))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    for case in 0..3 {
        let mut entries = entries.clone();
        match case {
            0 => entries.push(entries[0].clone()),
            1 => entries.reverse(),
            2 => {
                let relations = &mut entries
                    .iter_mut()
                    .find(|(name, _)| name == "file")
                    .unwrap()
                    .1;
                relations.push(relations[0].clone());
            }
            _ => unreachable!(),
        }
        // Borsh maps and sequences of key/value pairs share the same wire layout.
        let bytes = borsh::to_vec(&(
            retired.sequence,
            retired.phase,
            retired.relations.next,
            entries,
        ))
        .unwrap();
        let mut candidate = module.clone();
        candidate.store.put(&retired_key(&id), bytes);
        let before = candidate.store.serialize();
        assert!(candidate.validate_restored_state().is_err(), "case {case}");
        assert!(candidate.end_blocker(&block(2)).is_err(), "case {case}");
        assert_eq!(candidate.store.serialize(), before);
    }
}
