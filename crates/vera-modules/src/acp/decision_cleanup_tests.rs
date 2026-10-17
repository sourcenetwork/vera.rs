use super::*;

fn block(height: u64) -> BlockExecCtx {
    BlockExecCtx {
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 1000 + height,
            block_height: height,
        },
        ..Default::default()
    }
}

fn insert(module: &mut AcpModule, sequence: u64, issued: u64, size: usize) -> AccessDecision {
    let request = decision::DecisionRequest {
        deployment_id: block(issued).deployment_id,
        policy_id: "policy".into(),
        creator: "did:key:creator".into(),
        creator_sequence: sequence,
        request: AccessRequest {
            actor: Actor("did:key:actor".parse().unwrap()),
            operations: vec![types::Operation {
                object: Object {
                    resource: "file".into(),
                    id: "x".repeat(size),
                },
                permission: "read".into(),
            }],
        },
    };
    let record = AccessDecision {
        id: request.id().unwrap(),
        policy_id: request.policy_id,
        creator: request.creator,
        creator_acc_sequence: sequence,
        actor: request.request.actor.0.to_string(),
        operations: request.request.operations,
        params: DecisionParams {
            decision_expiration_delta: 100,
            ticket_expiration_delta: 100,
            proof_expiration_delta: 50,
        },
        creation_time: block(issued).timestamp,
        issued_height: issued,
    };
    module.store.put(
        &keys::access_decision_key(&record.id),
        borsh::to_vec(&record).unwrap(),
    );
    record
}

fn count(module: &AcpModule) -> usize {
    module
        .store
        .prefix_iter(keys::ACCESS_DECISION_PREFIX)
        .count()
}

fn restore(module: &AcpModule) -> AcpModule {
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    restored.validate_restored_state().unwrap();
    restored
}

#[test]
fn expiration_is_exclusive_and_end_block_preserves_live_records() {
    let mut module = AcpModule::new();
    let old = insert(&mut module, 1, 1, 1);
    let live = insert(&mut module, 2, 50, 1);
    module.end_blocker(&block(100)).unwrap();
    assert_eq!(
        module.query_access_decision(&old.id).unwrap(),
        Some(old.clone())
    );
    module.end_blocker(&block(101)).unwrap();
    assert_eq!(module.query_access_decision(&old.id).unwrap(), None);
    assert_eq!(module.query_access_decision(&live.id).unwrap(), Some(live));
    assert!(module.decision_cleanup_cursor().unwrap().is_none());
}

#[test]
fn bounded_batches_resume_after_restart_without_an_expiry_index() {
    let mut module = AcpModule::new();
    for sequence in 0..MAX_ITEMS * 2 + 1 {
        insert(&mut module, sequence as u64, 1, 1);
    }
    for remaining in [MAX_ITEMS + 1, 1, 0] {
        module.end_blocker(&block(101)).unwrap();
        assert_eq!(count(&module), remaining);
        module = restore(&module);
    }
    assert!(module.decision_cleanup_cursor().unwrap().is_none());
}

#[test]
fn byte_budget_limits_work_before_item_budget() {
    let mut module = AcpModule::new();
    for sequence in 0..MAX_ITEMS {
        insert(&mut module, sequence as u64, 1, 60_000);
    }
    let before = module.store.serialize();
    module.end_blocker(&block(101)).unwrap();
    let removed = MAX_ITEMS - count(&module);
    assert!(removed > 0 && removed < MAX_ITEMS);
    let original = InMemoryKvStore::deserialize(&before).unwrap();
    let bytes: usize = original
        .prefix_iter(keys::ACCESS_DECISION_PREFIX)
        .filter(|(key, _)| module.store.get_ref(key).is_none())
        .map(|(key, value)| key.len() + value.len())
        .sum();
    assert!(bytes <= MAX_BYTES);
    for _ in 0..MAX_ITEMS {
        module = restore(&module);
        module.end_blocker(&block(101)).unwrap();
    }
    assert_eq!(count(&module), 0);
}

#[test]
fn cursor_wraps_and_revisits_live_records_and_insertions_behind_it() {
    let mut module = AcpModule::new();
    for sequence in 0..MAX_ITEMS + 1 {
        insert(&mut module, sequence as u64, 50, 1);
    }
    module.end_blocker(&block(101)).unwrap();
    let cursor = module.decision_cleanup_cursor().unwrap().unwrap().to_vec();
    // Find an old decision whose hash sorts before the persisted cursor.
    let old = (1000..2000)
        .find_map(|sequence| {
            let old = insert(&mut module, sequence, 1, 1);
            if keys::access_decision_key(&old.id) < cursor {
                Some(old)
            } else {
                module.store.delete(&keys::access_decision_key(&old.id));
                None
            }
        })
        .unwrap();
    module = restore(&module);
    module.end_blocker(&block(101)).unwrap();
    assert!(module.query_access_decision(&old.id).unwrap().is_some());
    assert!(module.decision_cleanup_cursor().unwrap().is_none());
    for _ in 0..3 {
        module.end_blocker(&block(150)).unwrap();
    }
    assert_eq!(count(&module), 0);
}

#[test]
fn corruption_rejects_the_whole_lifecycle_batch() {
    for kind in 0..5 {
        let mut module = AcpModule::new();
        let a = insert(&mut module, 1, 1, 1);
        let b = insert(&mut module, 2, 1, 1);
        let mut records = [a, b];
        records.sort_by(|a, b| a.id.cmp(&b.id));
        let key = keys::access_decision_key(&records[1].id);
        match kind {
            0 => module.store.put(&key, vec![0]),
            1 => {
                records[1].params.decision_expiration_delta = u64::MAX;
                module.store.put(&key, borsh::to_vec(&records[1]).unwrap());
            }
            2 => {
                records[1].id = records[0].id.clone();
                module.store.put(&key, borsh::to_vec(&records[1]).unwrap());
            }
            3 => module.store.put(CURSOR_KEY, b"bad".to_vec()),
            _ => {
                module
                    .store
                    .delete(&keys::access_decision_key(&records[0].id));
                module.store.put(&key, vec![0; MAX_BYTES + 1]);
            }
        }
        let before = module.store.serialize();
        assert!(module.end_blocker(&block(101)).is_err(), "kind {kind}");
        assert_eq!(module.store.serialize(), before);
        if kind == 3 {
            assert!(module.validate_restored_state().is_err());
        }
    }
}

#[test]
fn zero_height_legacy_records_are_retained_and_do_not_block_progress() {
    let mut module = AcpModule::new();
    let mut legacy = insert(&mut module, 1, 1, 1);
    module.store.delete(&keys::access_decision_key(&legacy.id));
    legacy.id = "legacy-id".into();
    legacy.issued_height = 0;
    legacy.creation_time.block_height = 0;
    module.store.put(
        &keys::access_decision_key(&legacy.id),
        borsh::to_vec(&legacy).unwrap(),
    );
    for sequence in 2..MAX_ITEMS as u64 + 2 {
        insert(&mut module, sequence, 1, 1);
    }
    for _ in 0..3 {
        module.end_blocker(&block(101)).unwrap();
        module = restore(&module);
    }
    assert_eq!(count(&module), 1);
    assert_eq!(
        module.query_access_decision(&legacy.id).unwrap(),
        Some(legacy)
    );
}
