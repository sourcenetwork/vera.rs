use super::registration_priority_tests::{commit, owner, reveal};
use super::registration_tests::{execute, setup};
use super::*;

pub(super) fn transfer(
    module: &mut AcpModule,
    from: &Did,
    to: &Did,
    policy: &str,
    object: &Object,
    at: u64,
) {
    execute(
        module,
        from,
        policy,
        PolicyCmd::TransferObject {
            object: object.clone(),
            new_owner: Actor(to.clone()),
        },
        at,
    )
    .unwrap();
}

pub(super) fn refused(
    module: &mut AcpModule,
    actor: &Did,
    policy: &str,
    commitment: &(u64, RegistrationProof),
    at: u64,
) {
    let before = module.store.serialize();
    assert!(matches!(
        reveal(module, actor, policy, commitment, at),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store.serialize(), before);
}

pub(super) fn restore(module: &AcpModule) -> AcpModule {
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    restored.validate_restored_state().unwrap();
    restored
}

pub(super) fn markers(module: &AcpModule) -> usize {
    module.store.prefix_iter(relinquishment::PREFIX).count()
}

#[test]
fn a_third_partys_older_commitment_amends_a_transferred_record_and_the_transferor_stays_refused() {
    let (mut module, first, second, policy, object) = setup();
    let third = Did::new("did:key:third").unwrap();
    let reserve = commit(&mut module, &first, &policy, &object, 4);
    let claim = commit(&mut module, &third, &policy, &object, 5);
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        6,
    )
    .unwrap();
    transfer(&mut module, &first, &second, &policy, &object, 7);
    let PolicyCmdResult::RevealRegistration {
        record,
        event: Some(event),
    } = reveal(&mut module, &third, &policy, &claim, 8).unwrap()
    else {
        panic!("expected amendment")
    };
    assert_eq!(record.metadata.creation_ts.block_height, 5);
    assert_eq!(event.previous_owner.0, second);
    refused(&mut module, &first, &policy, &reserve, 9);
    assert_eq!(
        owner(&module, &policy, &object).metadata.owner_did,
        third.to_string()
    );
    assert_eq!(markers(&module), 1);
}

#[test]
fn a_marker_survives_restoration_archive_and_unarchive() {
    let (mut module, first, second, policy, object) = setup();
    let reserve = commit(&mut module, &first, &policy, &object, 5);
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        6,
    )
    .unwrap();
    transfer(&mut module, &first, &second, &policy, &object, 7);
    let mut module = restore(&module);
    refused(&mut module, &first, &policy, &reserve, 8);
    for (command, at) in [
        (PolicyCmd::ArchiveObject(object.clone()), 9),
        (PolicyCmd::UnarchiveObject(object.clone()), 11),
    ] {
        execute(&mut module, &second, &policy, command, at).unwrap();
        let mut module = restore(&module);
        refused(&mut module, &first, &policy, &reserve, at + 1);
    }
    assert_eq!(markers(&module), 1);
}

#[test]
fn the_amendment_path_pays_for_the_marker_read() {
    let (mut module, first, second, policy, object) = setup();
    let claim = commit(&mut module, &second, &policy, &object, 5);
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        6,
    )
    .unwrap();
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 107,
            block_height: 7,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: second.to_string(),
        tx_hash: vec![7; 32],
        sequence: 7,
    };
    let amend = |module: &mut AcpModule, budget: &CommandBudget| {
        module.execute_policy_cmd_with_budget(
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: claim.0,
                proof: claim.1.clone(),
            },
            &block,
            &tx,
            budget,
        )
    };
    let unmarked = CommandBudget::new(u64::MAX);
    amend(&mut module.clone(), &unmarked).unwrap();

    // A marker for another actor leaves the claimant's read a miss of the same key length.
    let mut other = module.clone();
    other.store.put(
        &relinquishment::key(&policy, &object, "did:key:other"),
        Vec::new(),
    );
    let measured = CommandBudget::new(u64::MAX);
    amend(&mut other.clone(), &measured).unwrap();
    assert_eq!(measured.consumed(), unmarked.consumed());

    let mut marked = module.clone();
    marked.store.put(
        &relinquishment::key(&policy, &object, second.as_str()),
        Vec::new(),
    );
    let before = marked.store.serialize();
    let short = CommandBudget::new(unmarked.consumed() - 1);
    assert!(matches!(
        amend(&mut module, &short),
        Err(AcpError::CommandBudgetExceeded)
    ));
    let refusal = CommandBudget::new(u64::MAX);
    assert!(matches!(
        amend(&mut marked, &refusal),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(marked.store.serialize(), before);
    assert!(refusal.consumed() < unmarked.consumed());
    // The marker read is the refusal's last charge.
    assert!(matches!(
        amend(&mut marked, &CommandBudget::new(refusal.consumed() - 1)),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert_eq!(marked.store.serialize(), before);
}

#[test]
fn restoration_rejects_malformed_and_orphan_markers() {
    let (mut module, first, second, policy, object) = setup();
    let reserve = commit(&mut module, &first, &policy, &object, 4);
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        5,
    )
    .unwrap();
    transfer(&mut module, &first, &second, &policy, &object, 6);
    let key = relinquishment::key(&policy, &object, first.as_str());
    let unregistered = Object {
        resource: object.resource.clone(),
        id: "missing".into(),
    };
    let undeclared = Object {
        resource: "missing".into(),
        id: object.id.clone(),
    };
    let mut nonempty = module.store.clone();
    nonempty.put(&key, vec![0]);
    let mut cases = vec![nonempty];
    for extra in [
        relinquishment::key(&policy, &unregistered, first.as_str()),
        relinquishment::key(&policy, &undeclared, first.as_str()),
        relinquishment::key(&"f".repeat(64), &object, first.as_str()),
        [key.as_slice(), b"0"].concat(),
        [key.as_slice(), b"/00"].concat(),
        key[..key.len() - 2].to_vec(),
        [&key[..key.len() - 1], b"A"].concat(),
        [relinquishment::PREFIX, b"policy"].concat(),
    ] {
        let mut store = module.store.clone();
        store.put(&extra, Vec::new());
        cases.push(store);
    }
    for (case, store) in cases.into_iter().enumerate() {
        let mut restored = AcpModule::from_store(store);
        assert!(
            matches!(restored.validate_restored_state(), Err(AcpError::State(_))),
            "case {case}"
        );
        if case == 0 {
            let before = restored.store.serialize();
            assert!(matches!(
                reveal(&mut restored, &first, &policy, &reserve, 7),
                Err(AcpError::State(_))
            ));
            assert_eq!(restored.store.serialize(), before);
        }
    }
}

#[test]
fn retirement_removes_a_policys_markers_and_restores_at_every_step() {
    let (mut module, first, second, policy, object) = setup();
    let kept = module
        .create_policy(
            &second,
            "name: kept\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string();
    for (policy, owner, next) in [(&policy, &first, &second), (&kept, &second, &first)] {
        execute(
            &mut module,
            owner,
            policy,
            PolicyCmd::RegisterObject(object.clone()),
            5,
        )
        .unwrap();
        transfer(&mut module, owner, next, policy, &object, 6);
    }
    assert_eq!(markers(&module), 2);
    assert!(module.delete_policy(&first, &policy).unwrap());
    for height in 7..107 {
        if !module.policy_cleanup_pending(&policy).unwrap() {
            break;
        }
        module
            .end_blocker(&BlockExecCtx {
                timestamp: Timestamp {
                    seconds: height + 100,
                    block_height: height,
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
            .prefix_iter(&relinquishment::policy_prefix(&policy))
            .next()
            .is_none()
    );
    assert!(
        module
            .store
            .has(&relinquishment::key(&kept, &object, second.as_str()))
    );
}
