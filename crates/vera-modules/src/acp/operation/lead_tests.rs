//! The operator-selected lead of operation identities on policy commands.

use vera_crypto::operation::{DEFAULT_OPERATION_LEAD, MAX_OPERATION_LEAD};

use super::*;

const SIGNED: u64 = 100;
const HOUR: u64 = 3600;

fn policy(acp: &mut AcpModule) -> String {
    acp.create_policy(&vera_identity::Did::new(issuer()).unwrap(), POLICY, FORMAT)
        .unwrap()
        .policy
        .id
}

fn register(name: &str) -> PolicyCmd {
    PolicyCmd::RegisterObject(Object {
        resource: "file".into(),
        id: name.into(),
    })
}

fn state(acp: &AcpModule, vera: &VeraModule) -> (Vec<u8>, Vec<u8>) {
    (acp.store().serialize(), vera.store().serialize())
}

#[test]
fn the_default_lead_keeps_policy_commands_within_600_seconds() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let worker = submission(7);
    assert_eq!(acp.policy_operation_lead().unwrap(), DEFAULT_OPERATION_LEAD);
    let command = register("report");
    let call = DelegatedOperation::PolicyCommand(&policy, &command);
    let far = id(1, SIGNED + DEFAULT_OPERATION_LEAD + 1);
    let before = state(&acp, &vera);
    let error = acp
        .bearer_policy_cmd(
            &mut vera,
            &context(SIGNED),
            &worker,
            &token(&worker, far, &call),
            &policy,
            command.clone(),
        )
        .unwrap_err();
    assert!(
        matches!(&error, AcpError::InvalidBearerToken { .. }),
        "{error}"
    );
    assert_eq!(state(&acp, &vera), before);
    let near = id(2, SIGNED + DEFAULT_OPERATION_LEAD);
    acp.bearer_policy_cmd(
        &mut vera,
        &context(SIGNED),
        &worker,
        &token(&worker, near, &call),
        &policy,
        command,
    )
    .unwrap();
}

#[test]
fn a_raised_lead_lets_a_policy_command_run_hours_after_signing_exactly_once() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let (first, second) = (submission(7), submission(8));
    let command = register("owed");
    let call = DelegatedOperation::PolicyCommand(&policy, &command);
    let identity = id(1, SIGNED + 2 * HOUR);
    let signed = token(&first, identity, &call);
    let later = context(SIGNED + HOUR);
    let before = state(&acp, &vera);
    assert!(
        acp.bearer_policy_cmd(&mut vera, &later, &first, &signed, &policy, command.clone())
            .is_err()
    );
    assert_eq!(state(&acp, &vera), before);

    acp.set_policy_operation_lead(2 * HOUR).unwrap();
    let result = acp
        .bearer_policy_cmd(&mut vera, &later, &first, &signed, &policy, command.clone())
        .unwrap();
    assert!(
        acp.query_object_owner(
            &policy,
            &Object {
                resource: "file".into(),
                id: "owed".into()
            }
        )
        .unwrap()
        .0
    );
    let outcome = acp.operation(&issuer(), identity).unwrap().unwrap();
    assert_eq!(outcome.revision.seconds, SIGNED + HOUR);

    let before = acp.store().serialize();
    let replayed = acp
        .bearer_policy_cmd(
            &mut vera,
            &context(SIGNED + HOUR + 60),
            &second,
            &token(&second, identity, &call),
            &policy,
            command.clone(),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(replayed).unwrap(),
        serde_json::to_value(result).unwrap()
    );
    assert_eq!(acp.store().serialize(), before);

    let deadline = context(identity.expires_at());
    acp.end_blocker(&deadline).unwrap();
    assert!(acp.operation(&issuer(), identity).unwrap().is_none());
    assert_eq!(acp.operation_bytes().unwrap(), 0);
    let before = state(&acp, &vera);
    assert!(
        acp.bearer_policy_cmd(&mut vera, &deadline, &first, &signed, &policy, command)
            .is_err()
    );
    assert_eq!(state(&acp, &vera), before);
}

#[test]
fn a_raised_lead_leaves_other_operations_at_the_default() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    acp.set_policy_operation_lead(MAX_OPERATION_LEAD).unwrap();
    let worker = submission(7);
    let create = DelegatedOperation::CreatePolicy(POLICY, &FORMAT);
    let far = id(1, SIGNED + DEFAULT_OPERATION_LEAD + 1);
    let before = state(&acp, &vera);
    assert!(
        acp.bearer_create_policy(
            &mut vera,
            &context(SIGNED),
            &worker,
            &token(&worker, far, &create),
            POLICY,
            FORMAT
        )
        .is_err()
    );
    assert_eq!(state(&acp, &vera), before);
    let policy = policy(&mut acp);
    let command = register("report");
    let call = DelegatedOperation::PolicyCommand(&policy, &command);
    let beyond = id(2, SIGNED + MAX_OPERATION_LEAD + 1);
    let before = state(&acp, &vera);
    assert!(
        acp.bearer_policy_cmd(
            &mut vera,
            &context(SIGNED),
            &worker,
            &token(&worker, beyond, &call),
            &policy,
            command.clone()
        )
        .is_err()
    );
    assert_eq!(state(&acp, &vera), before);
    let longest = id(3, SIGNED + MAX_OPERATION_LEAD);
    acp.bearer_policy_cmd(
        &mut vera,
        &context(SIGNED),
        &worker,
        &token(&worker, longest, &call),
        &policy,
        command,
    )
    .unwrap();
}

#[test]
fn the_lead_is_bounded_and_a_malformed_record_is_a_state_error() {
    let mut acp = AcpModule::new();
    for seconds in [
        0,
        DEFAULT_OPERATION_LEAD - 1,
        MAX_OPERATION_LEAD + 1,
        u64::MAX,
    ] {
        let before = acp.store().serialize();
        assert!(acp.set_policy_operation_lead(seconds).is_err());
        assert_eq!(acp.store().serialize(), before);
    }
    for seconds in [DEFAULT_OPERATION_LEAD, MAX_OPERATION_LEAD] {
        acp.set_policy_operation_lead(seconds).unwrap();
        assert_eq!(acp.policy_operation_lead().unwrap(), seconds);
    }
    for malformed in [
        vec![0; 7],
        (DEFAULT_OPERATION_LEAD - 1).to_be_bytes().to_vec(),
    ] {
        acp.store
            .put(crate::acp::POLICY_OPERATION_LEAD_KEY, malformed);
        assert!(matches!(
            acp.policy_operation_lead(),
            Err(AcpError::State(_))
        ));
    }
}

#[test]
fn lowering_the_lead_reopens_no_identity_and_strands_no_record() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let worker = submission(7);
    acp.set_policy_operation_lead(2 * HOUR).unwrap();
    let claimed_command = register("claimed");
    let claimed_call = DelegatedOperation::PolicyCommand(&policy, &claimed_command);
    let claimed = id(1, SIGNED + 2 * HOUR);
    let claimed_token = token(&worker, claimed, &claimed_call);
    let result = acp
        .bearer_policy_cmd(
            &mut vera,
            &context(SIGNED),
            &worker,
            &claimed_token,
            &policy,
            claimed_command.clone(),
        )
        .unwrap();
    let pending_command = register("pending");
    let pending_call = DelegatedOperation::PolicyCommand(&policy, &pending_command);
    let pending = id(2, SIGNED + 2 * HOUR);
    let pending_token = token(&worker, pending, &pending_call);

    acp.set_policy_operation_lead(DEFAULT_OPERATION_LEAD)
        .unwrap();
    let early = context(SIGNED + 60);
    for (token, command) in [
        (&claimed_token, &claimed_command),
        (&pending_token, &pending_command),
    ] {
        let before = state(&acp, &vera);
        assert!(
            acp.bearer_policy_cmd(&mut vera, &early, &worker, token, &policy, command.clone())
                .is_err()
        );
        assert_eq!(state(&acp, &vera), before);
    }

    let within = context(claimed.expires_at() - DEFAULT_OPERATION_LEAD);
    let before = acp.store().serialize();
    let replayed = acp
        .bearer_policy_cmd(
            &mut vera,
            &within,
            &worker,
            &claimed_token,
            &policy,
            claimed_command.clone(),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(replayed).unwrap(),
        serde_json::to_value(result).unwrap()
    );
    assert_eq!(acp.store().serialize(), before);
    acp.bearer_policy_cmd(
        &mut vera,
        &within,
        &worker,
        &pending_token,
        &policy,
        pending_command.clone(),
    )
    .unwrap();

    let deadline = context(claimed.expires_at());
    acp.end_blocker(&deadline).unwrap();
    assert!(acp.operation(&issuer(), claimed).unwrap().is_none());
    assert!(acp.operation(&issuer(), pending).unwrap().is_none());
    assert_eq!(acp.operation_bytes().unwrap(), 0);
    for (token, command) in [
        (&claimed_token, claimed_command),
        (&pending_token, pending_command),
    ] {
        let before = state(&acp, &vera);
        assert!(
            acp.bearer_policy_cmd(&mut vera, &deadline, &worker, token, &policy, command)
                .is_err()
        );
        assert_eq!(state(&acp, &vera), before);
    }
}

#[test]
fn long_deadlines_stay_within_the_budget_and_the_cleanup_bound() {
    let mut acp = AcpModule::new();
    let mut vera = VeraModule::new();
    let policy = policy(&mut acp);
    let worker = submission(7);
    acp.set_policy_operation_lead(MAX_OPERATION_LEAD).unwrap();
    let floor = MAX_OPERATION_RECORD_BYTES as u64;
    acp.set_operation_budget(floor).unwrap();
    acp.store.put(BYTES_KEY, floor.to_be_bytes().to_vec());
    let command = register("full");
    let call = DelegatedOperation::PolicyCommand(&policy, &command);
    let longest = id(1, SIGNED + MAX_OPERATION_LEAD);
    let before = state(&acp, &vera);
    assert!(
        acp.bearer_policy_cmd(
            &mut vera,
            &context(SIGNED),
            &worker,
            &token(&worker, longest, &call),
            &policy,
            command
        )
        .is_err()
    );
    assert_eq!(state(&acp, &vera), before);
    acp.store.put(BYTES_KEY, 0u64.to_be_bytes().to_vec());

    let actor = issuer();
    let mut record = OperationRecord {
        id: longest,
        digest: [1; 32],
        actor: actor.clone(),
        submission: [7; 32],
        worker: worker.signer.clone(),
        revision: context(SIGNED).timestamp,
        result: serde_json::json!({"ok":true}),
    };
    let long_deadline = SIGNED + MAX_OPERATION_LEAD;
    for entropy in 1..=OPERATION_PRUNE_LIMIT + 1 {
        record.id = id(u8::try_from(entropy).unwrap(), long_deadline);
        acp.complete_operation(&actor, &record, None).unwrap();
    }
    let short = id(u8::MAX, SIGNED + DEFAULT_OPERATION_LEAD);
    record.id = short;
    acp.complete_operation(&actor, &record, None).unwrap();
    acp.prune_operations(short.expires_at()).unwrap();
    assert!(acp.operation(&actor, short).unwrap().is_none());
    let retained = OPERATION_PRUNE_LIMIT + 1;
    assert_eq!(acp.store.prefix_iter(EXPIRY_PREFIX).count(), retained);
    acp.prune_operations(long_deadline - 1).unwrap();
    assert_eq!(acp.store.prefix_iter(EXPIRY_PREFIX).count(), retained);
    acp.prune_operations(long_deadline).unwrap();
    assert_eq!(acp.store.prefix_iter(EXPIRY_PREFIX).count(), 1);
    acp.prune_operations(long_deadline).unwrap();
    assert_eq!(acp.store.prefix_iter(EXPIRY_PREFIX).count(), 0);
    assert_eq!(acp.operation_bytes().unwrap(), 0);
}
