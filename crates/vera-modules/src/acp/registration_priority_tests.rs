use super::registration_tests::{execute, setup};
use super::*;

fn commit(
    module: &mut AcpModule,
    actor: &Did,
    policy: &str,
    object: &Object,
    height: u64,
) -> (u64, RegistrationProof) {
    let generated = AcpModule::generate_registration_commitment(
        policy,
        std::slice::from_ref(object),
        &Actor(actor.clone()),
    )
    .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = execute(
        module,
        actor,
        policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        height,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    (registrations_commitment.id, generated.proofs[0].clone())
}

fn reveal(
    module: &mut AcpModule,
    actor: &Did,
    policy: &str,
    (id, proof): &(u64, RegistrationProof),
    height: u64,
) -> Result<PolicyCmdResult> {
    execute(
        module,
        actor,
        policy,
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: *id,
            proof: proof.clone(),
        },
        height,
    )
}

fn owner(module: &AcpModule, policy: &str, object: &Object) -> RelationshipRecord {
    module
        .registration_owner_record(policy, object)
        .unwrap()
        .unwrap()
}

fn rejected(
    module: &mut AcpModule,
    result: impl FnOnce(&mut AcpModule) -> Result<PolicyCmdResult>,
) {
    let before = module.store.serialize();
    let error = result(module).unwrap_err();
    assert!(
        matches!(
            error,
            AcpError::InvalidProof { .. } | AcpError::ObjectAlreadyRegistered { .. }
        ),
        "{error}"
    );
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn a_transferor_cannot_take_the_object_back_with_the_revealed_commitment() {
    let (mut module, first, second, policy, object) = setup();
    let commitment = commit(&mut module, &first, &policy, &object, 5);
    reveal(&mut module, &first, &policy, &commitment, 6).unwrap();
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::TransferObject {
            object: object.clone(),
            new_owner: Actor(second.clone()),
        },
        7,
    )
    .unwrap();
    rejected(&mut module, |module| {
        reveal(module, &first, &policy, &commitment, 8)
    });
    assert_eq!(
        owner(&module, &policy, &object).metadata.owner_did,
        second.to_string()
    );
}

#[test]
fn commitments_of_one_revision_cannot_amend_each_other() {
    let (mut module, first, second, policy, object) = setup();
    let early = commit(&mut module, &first, &policy, &object, 5);
    let tied = commit(&mut module, &second, &policy, &object, 5);
    reveal(&mut module, &first, &policy, &early, 6).unwrap();
    rejected(&mut module, |module| {
        reveal(module, &second, &policy, &tied, 7)
    });
    assert_eq!(
        owner(&module, &policy, &object).metadata.owner_did,
        first.to_string()
    );
}

#[test]
fn a_commitment_of_the_registration_revision_cannot_amend_it() {
    let (mut module, first, second, policy, object) = setup();
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        5,
    )
    .unwrap();
    let tied = commit(&mut module, &second, &policy, &object, 5);
    rejected(&mut module, |module| {
        reveal(module, &second, &policy, &tied, 6)
    });
}

#[test]
fn the_current_owner_cannot_amend_its_own_registration() {
    let (mut module, first, _, policy, object) = setup();
    let commitment = commit(&mut module, &first, &policy, &object, 5);
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        6,
    )
    .unwrap();
    rejected(&mut module, |module| {
        reveal(module, &first, &policy, &commitment, 7)
    });
}

#[test]
fn an_older_commitment_amends_an_archived_registration() {
    let (mut module, first, second, policy, object) = setup();
    let commitment = commit(&mut module, &second, &policy, &object, 5);
    for (command, height) in [
        (PolicyCmd::RegisterObject(object.clone()), 6),
        (PolicyCmd::ArchiveObject(object.clone()), 7),
    ] {
        execute(&mut module, &first, &policy, command, height).unwrap();
    }
    let PolicyCmdResult::RevealRegistration {
        record,
        event: Some(event),
    } = reveal(&mut module, &second, &policy, &commitment, 8).unwrap()
    else {
        panic!("expected amendment")
    };
    assert!(!record.archived);
    assert_eq!(record.metadata.creation_ts.block_height, 5);
    assert_eq!(event.previous_owner.0, first);
    let stored = owner(&module, &policy, &object);
    assert!(!stored.archived);
    assert_eq!(stored.metadata.owner_did, second.to_string());
    module.validate_restored_state().unwrap();
    assert!(matches!(
        execute(
            &mut module,
            &first,
            &policy,
            PolicyCmd::UnarchiveObject(object.clone()),
            9
        ),
        Err(AcpError::Unauthorized { .. })
    ));
}

#[test]
fn a_newer_commitment_leaves_an_archived_registration_reserved() {
    let (mut module, first, second, policy, object) = setup();
    for (command, height) in [
        (PolicyCmd::RegisterObject(object.clone()), 5),
        (PolicyCmd::ArchiveObject(object.clone()), 6),
    ] {
        execute(&mut module, &first, &policy, command, height).unwrap();
    }
    let commitment = commit(&mut module, &second, &policy, &object, 7);
    let before = module.store.serialize();
    assert!(matches!(
        reveal(&mut module, &second, &policy, &commitment, 8),
        Err(AcpError::ObjectAlreadyRegistered { .. })
    ));
    assert_eq!(module.store.serialize(), before);
    assert!(owner(&module, &policy, &object).archived);
}
