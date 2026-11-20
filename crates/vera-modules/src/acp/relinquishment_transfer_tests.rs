use super::registration_priority_tests::{commit, owner, reveal};
use super::registration_tests::{execute, setup};
use super::tests::{markers, refused, restore, transfer};
use super::*;

fn marked(module: &AcpModule, policy: &str, object: &Object, actor: &Did) -> bool {
    module
        .store
        .has(&relinquishment::key(policy, object, actor.as_str()))
}

#[test]
fn a_transfer_marks_the_previous_owner_clears_the_new_one_and_ignores_a_transfer_to_itself() {
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
    transfer(&mut module, &first, &first, &policy, &object, 6);
    assert_eq!(markers(&module), 0);
    transfer(&mut module, &first, &second, &policy, &object, 7);
    assert!(marked(&module, &policy, &object, &first));
    refused(&mut module, &first, &policy, &reserve, 8);

    transfer(&mut module, &second, &first, &policy, &object, 9);
    assert!(!marked(&module, &policy, &object, &first));
    assert!(marked(&module, &policy, &object, &second));
    assert_eq!(markers(&module), 1);
    let mut module = restore(&module);

    transfer(&mut module, &first, &second, &policy, &object, 10);
    assert!(marked(&module, &policy, &object, &first));
    assert!(!marked(&module, &policy, &object, &second));
    assert_eq!(markers(&module), 1);
    restore(&module);
}

#[test]
fn an_owner_who_received_the_object_back_reclaims_it_from_a_later_amendment() {
    let (mut module, first, second, policy, object) = setup();
    let third = Did::new("did:key:third").unwrap();
    let reserve = commit(&mut module, &first, &policy, &object, 3);
    let claim = commit(&mut module, &third, &policy, &object, 4);
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        5,
    )
    .unwrap();
    transfer(&mut module, &first, &second, &policy, &object, 6);
    transfer(&mut module, &second, &first, &policy, &object, 7);
    reveal(&mut module, &third, &policy, &claim, 8).unwrap();
    assert_eq!(
        owner(&module, &policy, &object).metadata.owner_did,
        third.to_string()
    );
    reveal(&mut module, &first, &policy, &reserve, 9).unwrap();
    assert_eq!(
        owner(&module, &policy, &object).metadata.owner_did,
        first.to_string()
    );
    assert!(marked(&module, &policy, &object, &second));
    restore(&module);
}

#[test]
fn a_managers_transfer_marks_the_owner_it_moved_the_object_from() {
    let (mut module, first, second, _, object) = setup();
    let manager = Did::new("did:key:manager").unwrap();
    let policy = module
        .create_policy(
            &first,
            "name: managed\nresources:\n  - name: file\n    relations:\n      - name: admin\n        types: [actor]\n        manages: [owner]\n",
            PolicyMarshalingType::ShortYaml, Default::default(),
        )
        .unwrap()
        .policy
        .id;
    let reserve = commit(&mut module, &first, &policy, &object, 4);
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        5,
    )
    .unwrap();
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::SetRelationship(Relationship::with_entity(
            object.resource.clone(),
            object.id.clone(),
            "admin",
            manager.clone(),
        )),
        6,
    )
    .unwrap();
    transfer(&mut module, &manager, &second, &policy, &object, 7);
    assert!(marked(&module, &policy, &object, &first));
    assert!(!marked(&module, &policy, &object, &manager));
    refused(&mut module, &first, &policy, &reserve, 8);
}

#[test]
fn a_reveal_of_an_unregistered_object_does_not_read_a_marker() {
    let (mut module, first, _, policy, object) = setup();
    let claim = commit(&mut module, &first, &policy, &object, 5);
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 106,
            block_height: 6,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: first.to_string(),
        tx_hash: vec![6; 32],
        sequence: 6,
    };
    let register = |module: &mut AcpModule, budget: &CommandBudget| {
        module.execute_policy_cmd_with_budget(
            &first,
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
    let baseline = CommandBudget::new(u64::MAX);
    register(&mut module.clone(), &baseline).unwrap();

    // A read of either marker would refuse the reveal or fail on the value.
    let key = relinquishment::key(&policy, &object, first.as_str());
    for value in [Vec::new(), vec![0]] {
        let mut marked = module.clone();
        marked.store.put(&key, value);
        let measured = CommandBudget::new(u64::MAX);
        register(&mut marked.clone(), &measured).unwrap();
        assert_eq!(measured.consumed(), baseline.consumed());
        register(
            &mut marked.clone(),
            &CommandBudget::new(baseline.consumed()),
        )
        .unwrap();
    }
}
