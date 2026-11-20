//! One operation identity over an ordered list of delegated policy commands.

use super::*;
use crate::acp::MAX_POLICY_COMMAND_LIST;

const READERS: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n";
const DEADLINE: u64 = 200;

fn policy(acp: &mut AcpModule) -> String {
    acp.create_policy(&vera_identity::Did::new(issuer()).unwrap(), READERS, FORMAT, Default::default())
        .unwrap()
        .policy
        .id
}

fn object(name: &str) -> Object {
    Object {
        resource: "file".into(),
        id: name.into(),
    }
}

fn register(policy: &str, name: &str) -> (String, PolicyCmd) {
    (policy.into(), PolicyCmd::RegisterObject(object(name)))
}

fn grant(policy: &str, name: &str) -> (String, PolicyCmd) {
    (
        policy.into(),
        PolicyCmd::SetRelationship(vera_acp::Relationship::with_entity(
            "file",
            name,
            "reader",
            vera_identity::Did::new(submission(9).signer).unwrap(),
        )),
    )
}

fn signed(worker: &TxExecCtx, id: OperationId, commands: &[(String, PolicyCmd)]) -> String {
    token(worker, id, &DelegatedOperation::PolicyCommandList(commands))
}

fn state(acp: &AcpModule, vera: &VeraModule) -> (Vec<u8>, Vec<u8>) {
    (acp.store().serialize(), vera.store().serialize())
}

fn owns(acp: &AcpModule, policy: &str, name: &str) -> bool {
    acp.query_object_owner(policy, &object(name)).unwrap().0
}

#[test]
fn a_signed_list_applies_in_order_once_for_every_worker_and_spelling() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let other = policy_with_name(&mut acp);
    let (first, second) = (submission(7), submission(8));
    let commands = vec![
        register(&policy, "report"),
        grant(&policy, "report"),
        register(&other, "notes"),
    ];
    let identity = id(1, DEADLINE);
    let first_token = signed(&first, identity, &commands);
    let results = acp
        .bearer_policy_cmds(&mut vera, &context(100), &first, &first_token, &commands)
        .unwrap();
    assert_eq!(results.len(), 3);
    assert!(owns(&acp, &policy, "report") && owns(&acp, &other, "notes"));
    let outcome = acp.operation(&issuer(), identity).unwrap().unwrap();
    assert_eq!(outcome.result, serde_json::to_value(&results).unwrap());
    assert_eq!(
        outcome.digest,
        DelegatedOperation::PolicyCommandList(&commands)
            .digest()
            .unwrap()
    );

    let before = acp.store().serialize();
    let replayed = acp
        .bearer_policy_cmds(
            &mut vera,
            &context(101),
            &second,
            &signed(&second, identity, &commands),
            &commands,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(replayed).unwrap(),
        serde_json::to_value(&results).unwrap()
    );
    assert_eq!(acp.store().serialize(), before);

    let mut alternate = vera_crypto::jwt::verify_bearer_token(&first_token).unwrap();
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let mut raw_key = vec![0xe7, 0x01];
    raw_key.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
    alternate.iss = format!("did:key:u{}", URL_SAFE_NO_PAD.encode(raw_key));
    let aliased = acp
        .bearer_policy_cmds(
            &mut vera,
            &context(102),
            &first,
            &sign(&alternate),
            &commands,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(aliased).unwrap(),
        serde_json::to_value(&results).unwrap()
    );
    assert_eq!(acp.store().serialize(), before);
}

fn policy_with_name(acp: &mut AcpModule) -> String {
    acp.create_policy(
        &vera_identity::Did::new(issuer()).unwrap(),
        "name: notes\nresources:\n  - name: file\n",
        FORMAT, Default::default(),
    )
    .unwrap()
    .policy
    .id
}

#[test]
fn a_reordered_shortened_extended_or_altered_list_is_refused() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let worker = submission(7);
    let commands = vec![register(&policy, "a"), register(&policy, "b")];
    let identity = id(1, DEADLINE);
    let authorized = signed(&worker, identity, &commands);
    let altered = [
        vec![commands[1].clone(), commands[0].clone()],
        vec![commands[0].clone()],
        vec![
            commands[0].clone(),
            commands[1].clone(),
            register(&policy, "c"),
        ],
        vec![commands[0].clone(), register(&policy, "B")],
    ];
    for list in &altered {
        let before = state(&acp, &vera);
        let error = acp
            .bearer_policy_cmds(&mut vera, &context(100), &worker, &authorized, list)
            .unwrap_err();
        assert!(
            matches!(&error, AcpError::InvalidBearerToken { .. }),
            "{error}"
        );
        assert_eq!(state(&acp, &vera), before);
    }
    let single = DelegatedOperation::PolicyCommand(&policy, &commands[0].1);
    let single_token = token(&worker, identity, &single);
    let before = state(&acp, &vera);
    assert!(
        acp.bearer_policy_cmds(
            &mut vera,
            &context(100),
            &worker,
            &single_token,
            &commands[..1]
        )
        .is_err()
    );
    assert_eq!(state(&acp, &vera), before);

    acp.bearer_policy_cmds(&mut vera, &context(100), &worker, &authorized, &commands)
        .unwrap();
    for list in &altered {
        let before = state(&acp, &vera);
        let reused = signed(&worker, identity, list);
        let error = acp
            .bearer_policy_cmds(&mut vera, &context(101), &worker, &reused, list)
            .unwrap_err();
        assert!(
            matches!(&error, AcpError::InvalidBearerToken { reason } if reason.contains("different arguments")),
            "{error}"
        );
        assert_eq!(state(&acp, &vera), before);
    }
}

#[test]
fn a_failed_list_claims_nothing_and_can_be_corrected_before_its_deadline() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let worker = submission(7);
    let identity = id(1, DEADLINE);
    let misordered = vec![grant(&policy, "report"), register(&policy, "report")];
    let partial = vec![register(&policy, "report"), grant(&policy, "missing")];
    for list in [&misordered, &partial] {
        let before = state(&acp, &vera);
        assert!(
            acp.bearer_policy_cmds(
                &mut vera,
                &context(100),
                &worker,
                &signed(&worker, identity, list),
                list
            )
            .is_err()
        );
        assert_eq!(state(&acp, &vera), before);
        assert!(acp.operation(&issuer(), identity).unwrap().is_none());
        assert!(!owns(&acp, &policy, "report"));
    }
    let corrected = vec![register(&policy, "report"), grant(&policy, "report")];
    acp.bearer_policy_cmds(
        &mut vera,
        &context(150),
        &worker,
        &signed(&worker, identity, &corrected),
        &corrected,
    )
    .unwrap();
    assert!(owns(&acp, &policy, "report"));
    assert!(acp.operation(&issuer(), identity).unwrap().is_some());
}

#[test]
fn list_length_and_policy_identifiers_are_checked_before_authorization() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let worker = submission(7);
    let too_long: Vec<_> = (0..=MAX_POLICY_COMMAND_LIST)
        .map(|index| register(&policy, &index.to_string()))
        .collect();
    let invalid = vec![register(&policy.to_uppercase(), "a")];
    for list in [Vec::new(), too_long, invalid] {
        let before = state(&acp, &vera);
        let error = acp
            .bearer_policy_cmds(
                &mut vera,
                &context(100),
                &worker,
                &signed(&worker, id(1, DEADLINE), &list),
                &list,
            )
            .unwrap_err();
        assert!(
            matches!(&error, AcpError::InvalidCommandList { .. }),
            "{error}"
        );
        assert_eq!(state(&acp, &vera), before);
    }
    let longest: Vec<_> = (0..MAX_POLICY_COMMAND_LIST)
        .map(|index| register(&policy, &index.to_string()))
        .collect();
    acp.bearer_policy_cmds(
        &mut vera,
        &context(100),
        &worker,
        &signed(&worker, id(2, DEADLINE), &longest),
        &longest,
    )
    .unwrap();
}

#[test]
fn a_list_signed_hours_ahead_needs_the_raised_lead() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let worker = submission(7);
    let commands = vec![register(&policy, "owed"), grant(&policy, "owed")];
    let identity = id(1, 100 + 7200);
    let authorized = signed(&worker, identity, &commands);
    let later = context(100 + 3600);
    let before = state(&acp, &vera);
    assert!(
        acp.bearer_policy_cmds(&mut vera, &later, &worker, &authorized, &commands)
            .is_err()
    );
    assert_eq!(state(&acp, &vera), before);
    acp.set_policy_operation_lead(7200).unwrap();
    acp.bearer_policy_cmds(&mut vera, &later, &worker, &authorized, &commands)
        .unwrap();
    let before = acp.store().serialize();
    acp.bearer_policy_cmds(
        &mut vera,
        &context(100 + 7000),
        &worker,
        &authorized,
        &commands,
    )
    .unwrap();
    assert_eq!(acp.store().serialize(), before);
}
