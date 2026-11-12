//! Tokens, operation outcomes, decisions and commitments under each spelling.

use super::*;
use vera_modules::acp::{
    decision::DecisionRequest,
    types::{AccessDecision, PolicyCmdResult},
};

fn json(value: &impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn an_operation_identity_has_one_outcome_for_every_issuer_spelling() {
    let (owner, first_worker) = (Key::new(42), worker(7));
    let (base, policy) = fixture(&owner);
    let command = PolicyCmd::RegisterObject(file("ledger"));
    let operation = DelegatedOperation::PolicyCommand(&policy, &command);
    let id = operation_id(1);
    let mut states = Vec::new();
    for first in owner.spellings() {
        let (mut acp, mut vera) = (base.clone(), VeraModule::new());
        let original = acp
            .bearer_policy_cmd(
                &mut vera,
                &context(100),
                &first_worker,
                &owner.operation_token(&first, &first_worker, id, &operation),
                &policy,
                command.clone(),
            )
            .unwrap();
        let after = acp.store().serialize();
        for (retry, issuer) in (8..).zip(owner.spellings()) {
            let retrying = worker(retry);
            let repeated = acp
                .bearer_policy_cmd(
                    &mut vera,
                    &context(101),
                    &retrying,
                    &owner.operation_token(&issuer, &retrying, id, &operation),
                    &policy,
                    command.clone(),
                )
                .unwrap();
            assert_eq!(json(&repeated), json(&original));
            assert_eq!(acp.store().serialize(), after);
            let outcome = acp.operation(&issuer, id).unwrap().unwrap();
            assert_eq!(outcome.actor, owner.canonical());
            assert_eq!(outcome.worker, first_worker.signer);
        }
        assert!(
            acp.operation(&Key::new(43).canonical(), id)
                .unwrap()
                .is_none()
        );
        states.push(after);
    }
    assert!(all_equal(&states));
}

#[test]
fn an_operation_binds_its_arguments_as_the_caller_wrote_them() {
    let (owner, grantee, worker) = (Key::new(42), Key::new(43), worker(7));
    let (mut acp, policy) = fixture(&owner);
    let mut vera = VeraModule::new();
    let grant = |spelling: usize| {
        PolicyCmd::SetRelationship(reader(Subject::Entity(grantee.dids()[spelling].clone())))
    };
    let (written, canonical) = (grant(1), grant(0));
    let token = owner.operation_token(
        &owner.canonical(),
        &worker,
        operation_id(1),
        &DelegatedOperation::PolicyCommand(&policy, &written),
    );
    let before = acp.store().serialize();
    assert!(
        acp.bearer_policy_cmd(
            &mut vera,
            &context(100),
            &worker,
            &token,
            &policy,
            canonical.clone()
        )
        .is_err(),
        "the signed digest covers the caller's spelling"
    );
    assert_eq!(acp.store().serialize(), before);

    let granted = acp
        .bearer_policy_cmd(&mut vera, &context(100), &worker, &token, &policy, written)
        .unwrap();
    let PolicyCmdResult::SetRelationship { record, .. } = &granted else {
        panic!("a grant returns its relationship");
    };
    assert_eq!(
        record.relationship.subject,
        Subject::Entity(grantee.dids()[0].clone())
    );

    let after = acp.store().serialize();
    let respelled = owner.operation_token(
        &owner.canonical(),
        &worker,
        operation_id(1),
        &DelegatedOperation::PolicyCommand(&policy, &canonical),
    );
    assert!(
        acp.bearer_policy_cmd(
            &mut vera,
            &context(101),
            &worker,
            &respelled,
            &policy,
            canonical
        )
        .is_err(),
        "a completed identity rejects different signed arguments"
    );
    assert_eq!(acp.store().serialize(), after);
}

#[test]
fn a_decision_names_its_actor_canonically_and_verifies_for_any_spelling() {
    let (owner, grantee, caller, worker) = (Key::new(42), Key::new(43), Key::new(44), worker(7));
    let (mut base, policy) = fixture(&owner);
    base.direct_policy_cmd(
        &owner.dids()[0],
        &policy,
        PolicyCmd::SetRelationship(reader(Subject::Entity(grantee.dids()[0].clone()))),
    )
    .unwrap();
    let at = context(101).timestamp;
    let (mut decisions, mut states) = (Vec::<AccessDecision>::new(), Vec::new());
    for (written, actor) in grantee.dids().into_iter().enumerate() {
        let (mut acp, mut vera) = (base.clone(), VeraModule::new());
        let mut record = |acp: &mut AcpModule, actor: &Did| {
            acp.bearer_check_access(
                &mut vera,
                &context(100),
                &worker,
                &caller.token(
                    &caller.spellings()[written],
                    &worker,
                    DelegationScope::RecordAccessDecision,
                ),
                &policy,
                &read(actor, file("report")),
            )
        };
        let decision = record(&mut acp, &actor).unwrap();
        assert_eq!(decision.actor, grantee.canonical());
        assert_eq!(
            acp.query_access_decision(&decision.id).unwrap().as_ref(),
            Some(&decision)
        );
        decision.verify_issuance(9001, &decision.id, &at).unwrap();
        for other in grantee.dids() {
            let expected = DecisionRequest {
                deployment_id: 9001,
                policy_id: policy.clone(),
                creator: worker.signer.clone(),
                creator_sequence: worker.sequence,
                request: read(&other, file("report")),
            };
            assert_eq!(expected.id().unwrap(), decision.id);
            let bytes = borsh::to_vec(&decision).unwrap();
            assert_eq!(expected.verify_record(&bytes, &at).unwrap(), decision);
        }
        states.push(acp.store().serialize());
        for holder in owner.dids() {
            assert_eq!(record(&mut acp, &holder).unwrap().actor, owner.canonical());
        }
        assert!(record(&mut acp, &caller.dids()[written]).is_err());
        decisions.push(decision);
    }
    assert!(decisions.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(all_equal(&states));
}

#[test]
fn a_decision_names_a_secp256k1_creator_canonically() {
    let (owner, creator) = (Key::new(42), Key::new(9));
    let (mut acp, policy) = fixture(&owner);
    let request = read(&owner.dids()[1], file("report"));
    let mut decisions = Vec::new();
    for signer in creator.dids() {
        let submission = TxExecCtx {
            signer: signer.to_string(),
            tx_hash: vec![9; 32],
            sequence: 3,
        };
        let decision = acp
            .check_access(&signer, &policy, &request, &context(100), &submission)
            .unwrap();
        assert_eq!(decision.creator, creator.canonical());
        assert_eq!(decision.actor, owner.canonical());
        decisions.push(decision);
    }
    assert!(decisions.windows(2).all(|pair| pair[0] == pair[1]));
    let decision = decisions.remove(0);
    for spelling in creator.spellings() {
        let expected = DecisionRequest {
            deployment_id: 9001,
            policy_id: policy.clone(),
            creator: spelling,
            creator_sequence: 3,
            request: request.clone(),
        };
        expected
            .verify_issuance(&decision, &context(101).timestamp)
            .unwrap();
    }
    let mut respelled = decision.clone();
    respelled.actor = owner.spellings()[1].clone();
    assert!(
        respelled
            .verify_issuance(9001, &decision.id, &context(101).timestamp)
            .is_err(),
        "a stored decision must name its actor canonically"
    );
}

#[test]
fn a_registration_commitment_binds_the_canonical_actor() {
    let (owner, worker) = (Key::new(42), worker(7));
    let (base, policy) = fixture(&owner);
    let objects = [file("first"), file("second")];
    let commitments: Vec<_> = owner
        .dids()
        .into_iter()
        .map(|actor| {
            AcpModule::generate_registration_commitment(&policy, &objects, &Actor(actor))
                .unwrap()
                .commitment
        })
        .collect();
    assert!(all_equal(&commitments));

    // The leaf budget is spent on the canonical actor, whichever spelling asks.
    let leaf = policy.len() + owner.canonical().len() + "vera/registration-leaf/v1\0".len() + 16;
    let largest: Vec<_> = (0..64)
        .map(|index| {
            file(&format!(
                "{index:0width$}",
                width = 1024 - leaf - "file".len()
            ))
        })
        .collect();
    for actor in owner.dids() {
        base.query_generate_commitment(&policy, &largest, &Actor(actor.clone()))
            .unwrap();
        AcpModule::generate_registration_commitment(&policy, &largest, &Actor(actor)).unwrap();
    }
    let mut oversized = largest;
    oversized[0].id.push('0');
    assert!(
        AcpModule::generate_registration_commitment(
            &policy,
            &oversized,
            &Actor(owner.dids()[0].clone())
        )
        .is_err()
    );

    let mut states = Vec::new();
    for written in 0..4 {
        let (mut acp, mut vera) = (base.clone(), VeraModule::new());
        let generated = acp
            .query_generate_commitment(&policy, &objects, &Actor(owner.dids()[written].clone()))
            .unwrap();
        assert_eq!(generated.commitment, commitments[0]);
        let mut command = |acp: &mut AcpModule, spelling: usize, now, command| {
            acp.bearer_policy_cmd(
                &mut vera,
                &context(now),
                &worker,
                &owner.token(
                    &owner.spellings()[spelling % 4],
                    &worker,
                    DelegationScope::PolicyCommands,
                ),
                &policy,
                command,
            )
            .unwrap()
        };
        let committed = command(
            &mut acp,
            written,
            100,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment.clone(),
            },
        );
        let PolicyCmdResult::CommitRegistrations {
            registrations_commitment,
        } = committed
        else {
            panic!("a commitment returns its record");
        };
        assert_eq!(
            registrations_commitment.metadata.owner_did,
            owner.canonical()
        );
        let revealed = command(
            &mut acp,
            written + 1,
            101,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: generated.proofs[0].clone(),
            },
        );
        let PolicyCmdResult::RevealRegistration {
            record,
            event: None,
        } = revealed
        else {
            panic!("a reveal registers the object");
        };
        assert_eq!(record.metadata.owner_did, owner.canonical());
        states.push(acp.store().serialize());
    }
    assert!(all_equal(&states));
}
