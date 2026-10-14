use super::*;
use crate::acp::{
    decision::DecisionRequest,
    types::{AccessRequest, Actor, Operation},
};

fn fixture() -> (AcpModule, VeraModule, String, AccessRequest) {
    let mut acp = AcpModule::new();
    let owner = vera_identity::Did::new(issuer()).unwrap();
    let policy = acp.create_policy(&owner,
        "name: decisions\nresources:\n  - name: file\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n", FORMAT).unwrap().policy.id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    acp.direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    let target = vera_identity::Did::new(format!("did:opk:{}", "cd".repeat(32))).unwrap();
    acp.direct_policy_cmd(
        &owner,
        &policy,
        PolicyCmd::SetRelationship(vera_acp::Relationship::with_entity(
            "file",
            "report",
            "reader",
            target.clone(),
        )),
    )
    .unwrap();
    (
        acp,
        VeraModule::new(),
        policy,
        AccessRequest {
            actor: Actor(target),
            operations: vec![Operation {
                object,
                permission: "read".into(),
            }],
        },
    )
}

#[test]
fn decision_retries_preserve_issuance_across_workers_revocation_and_expiry() {
    let (mut acp, mut vera, policy, request) = fixture();
    let first = submission(7);
    let mut second = submission(8);
    second.sequence = 12;
    let operation_id = id(91, 400);
    let operation = DelegatedOperation::CheckAccess(&policy, &request);
    let original = acp
        .bearer_check_access(
            &mut vera,
            &context(100),
            &first,
            &token(&first, operation_id, &operation),
            &policy,
            &request,
        )
        .unwrap();
    assert_eq!(original.creator, first.signer);
    assert_eq!(original.actor, request.actor.0.as_str());
    assert_ne!(original.creator, original.actor);
    let expected = DecisionRequest {
        deployment_id: 9001,
        policy_id: policy.clone(),
        creator: first.signer.clone(),
        creator_sequence: first.sequence,
        request: request.clone(),
    };
    assert_eq!(original.id, expected.id().unwrap());
    acp.direct_policy_cmd(
        &vera_identity::Did::new(issuer()).unwrap(),
        &policy,
        PolicyCmd::ArchiveObject(request.operations[0].object.clone()),
    )
    .unwrap();
    let mut acp =
        AcpModule::from_store(InMemoryKvStore::deserialize(&acp.store().serialize()).unwrap());
    let before = acp.store().serialize();
    let retry = acp
        .bearer_check_access(
            &mut vera,
            &context(201),
            &second,
            &token(&second, operation_id, &operation),
            &policy,
            &request,
        )
        .unwrap();
    assert_eq!(original, retry);
    assert_eq!(acp.store().serialize(), before);
    assert!(
        expected
            .verify_record(&borsh::to_vec(&retry).unwrap(), &context(201).timestamp)
            .is_err()
    );
    let fresh = id(92, 400);
    assert!(
        acp.bearer_check_access(
            &mut vera,
            &context(201),
            &second,
            &token(&second, fresh, &operation),
            &policy,
            &request
        )
        .is_err()
    );
    assert!(acp.operation(&issuer(), fresh).unwrap().is_none());
    let mut changed = request.clone();
    changed.operations[0].object.id = "different".into();
    assert!(
        acp.bearer_check_access(
            &mut vera,
            &context(201),
            &second,
            &token(
                &second,
                operation_id,
                &DelegatedOperation::CheckAccess(&policy, &changed)
            ),
            &policy,
            &changed
        )
        .is_err()
    );
    assert_eq!(acp.store().serialize(), before);
}

#[test]
fn decision_scope_and_outcome_budget_fail_without_partial_records() {
    let (mut acp, mut vera, policy, request) = fixture();
    let worker = submission(7);
    let operation_id = id(93, 400);
    let operation = DelegatedOperation::CheckAccess(&policy, &request);
    let valid = token(&worker, operation_id, &operation);
    let mut claims = vera_crypto::jwt::verify_bearer_token(&valid).unwrap();
    claims.scope = vera_crypto::jwt::DelegationScope::PolicyCommands;
    let before = (acp.store().serialize(), vera.store().serialize());
    assert!(
        acp.bearer_check_access(
            &mut vera,
            &context(100),
            &worker,
            &sign(&claims),
            &policy,
            &request
        )
        .is_err()
    );
    assert_eq!((acp.store().serialize(), vera.store().serialize()), before);
    acp.store.put(BUDGET_KEY, 1u64.to_be_bytes().to_vec());
    let before = (acp.store().serialize(), vera.store().serialize());
    assert!(
        acp.bearer_check_access(&mut vera, &context(100), &worker, &valid, &policy, &request)
            .is_err()
    );
    assert_eq!((acp.store().serialize(), vera.store().serialize()), before);
    assert!(acp.operation(&issuer(), operation_id).unwrap().is_none());
}
