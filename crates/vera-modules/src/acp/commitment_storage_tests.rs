use super::*;

fn actor(name: &str) -> Did {
    Did::new(format!("did:key:{name}")).unwrap()
}
fn fixture() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(
            &actor("owner"),
            "name: auxiliary\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    (module, policy)
}
fn record(policy: &str) -> RegistrationsCommitment {
    RegistrationsCommitment {
        id: 0,
        policy_id: policy.into(),
        commitment: vec![7; 32],
        expired: false,
        validity: Duration::Seconds(5),
        metadata: RecordMetadata {
            creation_ts: Timestamp {
                seconds: 100,
                block_height: 1,
            },
            tx_hash: vec![1; 32],
            tx_signer: actor("owner").to_string(),
            owner_did: actor("owner").to_string(),
        },
    }
}
fn read_price(store: &InMemoryKvStore, key: &[u8]) -> u64 {
    100 + (key.len() as u64 + store.get_ref(key).map_or(0, |v| v.len()) as u64).div_ceil(16)
}
fn write_price(key: &[u8], value: &[u8]) -> u64 {
    200 + 2 * (key.len() as u64 + value.len() as u64).div_ceil(16)
}
fn indexes(record: &RegistrationsCommitment) -> [Vec<u8>; 3] {
    [
        AcpModule::commitment_expiry_key(record),
        keys::commitment_by_commitment_index_key(&record.commitment, record.id),
        keys::commitment_policy_index_key(&record.policy_id, record.id),
    ]
}

#[test]
fn commitment_plans_reserve_each_record_counter_and_index_once() {
    let (original, policy) = fixture();
    let mut created = record(&policy);
    created.id = 1;
    let key = keys::commitment_key(1);
    let counter = keys::commitment_counter_key();
    let encoded = borsh::to_vec(&created).unwrap();
    let creation_cost = read_price(&original.store, &counter)
        + read_price(&original.store, &key)
        + write_price(&counter, &1u64.to_be_bytes())
        + write_price(&key, &encoded)
        + indexes(&created)
            .iter()
            .map(|key| write_price(key, &[]))
            .sum::<u64>();
    let mut exact = original.clone();
    let budget = CommandBudget::new(creation_cost);
    exact
        .create_commitment_with_budget(&mut record(&policy), Some(&budget))
        .unwrap();
    assert_eq!(budget.consumed(), creation_cost);
    assert_eq!(exact.store.diff_from(&original.store).len(), 5);
    exact.validate_restored_state().unwrap();
    let mut short = original.clone();
    let budget = CommandBudget::new(creation_cost - 1);
    let result = short.create_commitment_with_budget(&mut record(&policy), Some(&budget));
    assert!(matches!(
        budget.finish(result),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert_eq!(short.store.serialize(), original.store.serialize());

    let original = exact;
    let mut updated = created.clone();
    updated.metadata.creation_ts.seconds = 200;
    updated.commitment = vec![8; 32];
    let encoded = borsh::to_vec(&updated).unwrap();
    let update_cost = read_price(&original.store, &key)
        + write_price(&key, &encoded)
        + indexes(&created)
            .iter()
            .chain(indexes(&updated).iter())
            .map(|key| write_price(key, &[]))
            .sum::<u64>();
    let mut exact = original.clone();
    let budget = CommandBudget::new(update_cost);
    exact
        .update_commitment_with_budget(&updated, Some(&budget))
        .unwrap();
    assert_eq!(budget.consumed(), update_cost);
    for key in indexes(&updated) {
        assert_eq!(exact.store.get_ref(&key), Some(&[][..]));
    }
    assert!(
        exact
            .store
            .get_ref(&AcpModule::commitment_expiry_key(&created))
            .is_none()
    );
    assert!(
        exact
            .query_registrations_commitment_by_commitment(&created.commitment)
            .unwrap()
            .is_empty()
    );
    exact.validate_restored_state().unwrap();
    let mut short = original.clone();
    let budget = CommandBudget::new(update_cost - 1);
    let result = short.update_commitment_with_budget(&updated, Some(&budget));
    assert!(matches!(
        budget.finish(result),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert_eq!(short.store.serialize(), original.store.serialize());
    let mut restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&exact.store.serialize()).unwrap());
    assert!(
        restored
            .expire_commitments(&Timestamp {
                seconds: 205,
                block_height: 3
            })
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        restored
            .expire_commitments(&Timestamp {
                seconds: 206,
                block_height: 3
            })
            .unwrap(),
        vec![RegistrationsCommitment {
            expired: true,
            ..updated
        }]
    );
    restored.validate_restored_state().unwrap();
}

fn context(actor: &Did, height: u64) -> (BlockExecCtx, TxExecCtx) {
    (
        BlockExecCtx {
            timestamp: Timestamp {
                seconds: height * 10,
                block_height: height,
            },
            ..Default::default()
        },
        TxExecCtx {
            signer: actor.to_string(),
            tx_hash: vec![1; 32],
            sequence: height,
        },
    )
}
fn execute(
    module: &mut AcpModule,
    policy: &str,
    name: &str,
    command: PolicyCmd,
    height: u64,
) -> PolicyCmdResult {
    let actor = actor(name);
    let (block, tx) = context(&actor, height);
    module
        .execute_policy_cmd(&actor, policy, command, &block, &tx)
        .unwrap()
}

#[test]
fn contextual_commitment_restamp_is_atomic_at_the_last_index_reservation() {
    let (original, policy) = fixture();
    let actor = actor("owner");
    let (block, tx) = context(&actor, 10);
    let command = PolicyCmd::CommitRegistrations {
        commitment: vec![7; 32],
    };
    let mut measured = original.clone();
    let budget = CommandBudget::new(u64::MAX);
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment: record,
    } = measured
        .execute_policy_cmd_with_budget(&actor, &policy, command.clone(), &block, &tx, &budget)
        .unwrap()
    else {
        panic!("expected commitment")
    };
    assert_eq!(record.metadata.creation_ts, block.timestamp);
    assert_eq!(
        measured
            .store
            .prefix_iter(commitment_expiry::SECONDS_PREFIX)
            .count(),
        1
    );
    let mut transient = record;
    transient.metadata.creation_ts = Timestamp::default();
    assert!(
        measured
            .store
            .get_ref(&AcpModule::commitment_expiry_key(&transient))
            .is_none()
    );
    let mut exact = original.clone();
    exact
        .execute_policy_cmd_with_budget(
            &actor,
            &policy,
            command.clone(),
            &block,
            &tx,
            &CommandBudget::new(budget.consumed()),
        )
        .unwrap();
    assert_eq!(exact.store.serialize(), measured.store.serialize());
    exact.validate_restored_state().unwrap();
    let mut short = original.clone();
    let low = CommandBudget::new(budget.consumed() - 1);
    assert!(matches!(
        short.execute_policy_cmd_with_budget(&actor, &policy, command, &block, &tx, &low),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert!(low.is_exhausted());
    assert_eq!(short.store.serialize(), original.store.serialize());
}

#[test]
fn commitment_errors_retain_read_work_before_decoding_or_mutation() {
    let (module, policy) = fixture();
    for (key, bytes) in [
        (keys::PARAMS_KEY.to_vec(), vec![0; 1 << 20]),
        (keys::commitment_counter_key(), vec![0; 1 << 20]),
        (
            keys::commitment_counter_key(),
            u64::MAX.to_be_bytes().to_vec(),
        ),
        (keys::commitment_key(1), vec![0; 1 << 20]),
    ] {
        let mut corrupt = module.clone();
        corrupt.store.put(&key, bytes);
        let before = corrupt.store.serialize();
        let command = PolicyCmd::CommitRegistrations {
            commitment: vec![7; 32],
        };
        let budget = CommandBudget::new(u64::MAX);
        assert!(matches!(
            corrupt.direct_policy_cmd_with_budget(
                &actor("owner"),
                &policy,
                command.clone(),
                &budget
            ),
            Err(AcpError::State(_))
        ));
        assert!(budget.consumed() >= read_price(&corrupt.store, &key));
        if corrupt.store.get_ref(&key).unwrap().len() == 1 << 20 {
            let low = CommandBudget::new(10_000);
            assert!(matches!(
                corrupt.direct_policy_cmd_with_budget(&actor("owner"), &policy, command, &low),
                Err(AcpError::CommandBudgetExceeded)
            ));
        }
        assert_eq!(corrupt.store.serialize(), before);
    }
}

#[test]
fn hijack_flag_charges_authorization_reads_and_rewrites_without_partial_effects() {
    let (mut module, policy) = fixture();
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let generated = module
        .query_generate_commitment(
            &policy,
            std::slice::from_ref(&object),
            &Actor(actor("claimant")),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = execute(
        &mut module,
        &policy,
        "claimant",
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        1,
    )
    else {
        panic!("expected commitment")
    };
    execute(
        &mut module,
        &policy,
        "owner",
        PolicyCmd::RegisterObject(object),
        2,
    );
    let PolicyCmdResult::RevealRegistration {
        event: Some(event), ..
    } = execute(
        &mut module,
        &policy,
        "claimant",
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        },
        3,
    )
    else {
        panic!("expected amendment")
    };
    let command = PolicyCmd::FlagHijackAttempt { event_id: event.id };
    let original = module.clone();
    for previously_flagged in [false, true] {
        assert_eq!(
            module
                .get_amendment_event_by_id(event.id)
                .unwrap()
                .unwrap()
                .hijack_flag,
            previously_flagged
        );
        let before = module.store.serialize();
        let budget = CommandBudget::new(u64::MAX);
        let mut measured = module.clone();
        let PolicyCmdResult::FlagHijackAttempt { event: flagged } = measured
            .direct_policy_cmd_with_budget(&actor("claimant"), &policy, command.clone(), &budget)
            .unwrap()
        else {
            panic!("expected flag")
        };
        assert!(flagged.hijack_flag);
        assert_eq!(flagged.metadata, event.metadata);
        measured.validate_restored_state().unwrap();
        let mut low = module.clone();
        assert!(matches!(
            low.direct_policy_cmd_with_budget(
                &actor("claimant"),
                &policy,
                command.clone(),
                &CommandBudget::new(budget.consumed() - 1)
            ),
            Err(AcpError::CommandBudgetExceeded)
        ));
        assert_eq!(low.store.serialize(), before);
        module
            .direct_policy_cmd_with_budget(
                &actor("claimant"),
                &policy,
                command.clone(),
                &CommandBudget::new(budget.consumed()),
            )
            .unwrap();
        assert_eq!(module.store.serialize(), measured.store.serialize());
    }
    let budget = CommandBudget::new(u64::MAX);
    let before = module.store.serialize();
    assert!(matches!(
        module.direct_policy_cmd_with_budget(&actor("stranger"), &policy, command.clone(), &budget),
        Err(AcpError::Unauthorized { .. })
    ));
    assert!(budget.consumed() > read_price(&module.store, &keys::amendment_event_key(event.id)));
    assert_eq!(module.store.serialize(), before);
    let mut corrupt = original;
    corrupt
        .store
        .put(&keys::amendment_event_key(event.id), vec![0; 1 << 20]);
    let before = corrupt.store.serialize();
    assert!(matches!(
        corrupt.direct_policy_cmd_with_budget(
            &actor("claimant"),
            &policy,
            command.clone(),
            &CommandBudget::new(10_000)
        ),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert!(matches!(
        corrupt.direct_policy_cmd(&actor("claimant"), &policy, command),
        Err(AcpError::State(_))
    ));
    assert_eq!(corrupt.store.serialize(), before);
}
