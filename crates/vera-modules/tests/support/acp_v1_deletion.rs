use super::*;
use vera_modules::{acp::keys, kv_store::ModuleKvStore};

fn command(
    module: &mut AcpModule,
    policy: &str,
    actor: &str,
    command: PolicyCmd,
    height: u64,
) -> PolicyCmdResult {
    module
        .execute_policy_cmd(
            &did(actor),
            policy,
            command,
            &BlockExecCtx {
                timestamp: Timestamp {
                    seconds: height * 10,
                    block_height: height,
                },
                ..Default::default()
            },
            &TxExecCtx {
                signer: did(actor).to_string(),
                tx_hash: vec![1; 32],
                sequence: 0,
            },
        )
        .unwrap()
}

fn registration(module: &mut AcpModule, policy: &str, id: &str, height: u64) -> (u64, u64) {
    let object = Object {
        resource: "file".into(),
        id: id.into(),
    };
    let generated = module
        .query_generate_commitment(
            policy,
            std::slice::from_ref(&object),
            &Actor(did("claimant")),
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
        panic!("expected commitment")
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
        panic!("expected amendment")
    };
    (registrations_commitment.id, event.id)
}

#[test]
fn policy_deletion_indexes_survive_metadata_updates_expiry_and_restore() {
    let (mut module, policy) = setup();
    let expired = registration(&mut module, &policy, "expired", 2);
    let expired_record = module.query_registrations_commitment(expired.0).unwrap();
    assert_eq!(expired_record.metadata.creation_ts.block_height, 2);
    module
        .end_blocker(&BlockExecCtx {
            timestamp: Timestamp {
                seconds: 630,
                block_height: 63,
            },
            ..Default::default()
        })
        .unwrap();
    assert!(
        module
            .query_registrations_commitment(expired.0)
            .unwrap()
            .expired
    );
    assert_eq!(
        module
            .store()
            .get_ref(&keys::commitment_policy_index_key(&policy, expired.0)),
        Some(&[][..])
    );
    let active = registration(&mut module, &policy, "active", 64);
    let other = module
        .create_policy(&did("creator"), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let retained = registration(&mut module, &other, "retained", 64);
    let commitment = module.query_registrations_commitment(retained.0).unwrap();
    let event = module
        .get_amendment_event_by_id(retained.1)
        .unwrap()
        .unwrap();
    let mut module = restored(&module);
    module.validate_restored_state().unwrap();
    assert!(module.delete_policy(&did("creator"), &policy).unwrap());
    let mut module = restored(&module);
    module.validate_restored_state().unwrap();
    for (commitment, amendment) in [expired, active] {
        assert!(module.query_registrations_commitment(commitment).is_err());
        assert!(
            module
                .get_amendment_event_by_id(amendment)
                .unwrap()
                .is_none()
        );
    }
    // Logical deletion is immediate; physical ownership indexes remain until cleanup.
    assert_eq!(
        module
            .store()
            .prefix_iter(&keys::commitment_policy_index_prefix(&policy))
            .count(),
        2
    );
    for height in 70..90 {
        module
            .end_blocker(&BlockExecCtx {
                timestamp: Timestamp {
                    seconds: height * 10,
                    block_height: height,
                },
                ..Default::default()
            })
            .unwrap();
        module = restored(&module);
        module.validate_restored_state().unwrap();
    }
    assert_eq!(
        module
            .store()
            .prefix_iter(&keys::commitment_policy_index_prefix(&policy))
            .count(),
        0
    );
    assert_eq!(
        module
            .store()
            .prefix_iter(&keys::amendment_event_policy_index_prefix(&policy))
            .count(),
        0
    );
    assert_eq!(
        module.query_registrations_commitment(retained.0).unwrap(),
        commitment
    );
    assert_eq!(
        module
            .get_amendment_event_by_id(retained.1)
            .unwrap()
            .unwrap(),
        event
    );
    assert_eq!(
        module
            .store()
            .prefix_iter(&keys::commitment_policy_index_prefix(&other))
            .count(),
        1
    );
}

#[test]
fn indexed_policy_cleanup_rejects_corruption_without_partial_tick_mutation() {
    let (mut module, policy) = setup();
    registration(&mut module, &policy, "first", 2);
    let last = registration(&mut module, &policy, "last", 2);
    let other = module
        .create_policy(&did("creator"), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let foreign = registration(&mut module, &other, "foreign", 2);
    module.validate_restored_state().unwrap();
    let mut malformed = keys::commitment_policy_index_key(&policy, last.0);
    malformed.push(0);
    let mutations = [
        (
            keys::commitment_policy_index_key(&policy, last.0),
            Some(vec![1]),
        ),
        (keys::commitment_policy_index_key(&policy, 0), Some(vec![])),
        (keys::commitment_policy_index_key(&policy, 99), Some(vec![])),
        (
            keys::commitment_policy_index_key(&policy, foreign.0),
            Some(vec![]),
        ),
        (malformed, Some(vec![])),
        (keys::commitment_key(last.0), None),
        (keys::commitment_key(last.0), Some(vec![1])),
        (
            keys::amendment_event_policy_index_key(&policy, last.1),
            Some(vec![1]),
        ),
        (
            keys::amendment_event_policy_index_key(&policy, 0),
            Some(vec![]),
        ),
        (
            keys::amendment_event_policy_index_key(&policy, 99),
            Some(vec![]),
        ),
        (
            keys::amendment_event_policy_index_key(&policy, foreign.1),
            Some(vec![]),
        ),
        (keys::amendment_event_key(last.1), None),
        (keys::amendment_event_key(last.1), Some(vec![1])),
    ];
    for (key, value) in mutations {
        let mut store = module.store().clone();
        match value {
            Some(bytes) => store.put(&key, bytes),
            None => store.delete(&key),
        }
        let mut candidate = AcpModule::from_store(store);
        assert!(candidate.delete_policy(&did("creator"), &policy).unwrap());
        assert!(candidate.query_policy(&policy).is_err());
        let mut rejected = false;
        for height in 10..30 {
            let before = candidate.store().serialize();
            if candidate
                .end_blocker(&BlockExecCtx {
                    timestamp: Timestamp {
                        seconds: height * 10,
                        block_height: height,
                    },
                    ..Default::default()
                })
                .is_err()
            {
                assert_eq!(candidate.store().serialize(), before, "{key:?}");
                rejected = true;
                break;
            }
        }
        assert!(rejected, "cleanup accepted corrupt key: {key:?}");
        assert!(candidate.query_policy(&policy).is_err());
        assert!(candidate.query_policy(&other).is_ok());
    }
}
