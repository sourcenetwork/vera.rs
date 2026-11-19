//! Operator approval of the lead allowed to policy-command operation identities.

use vera_crypto::operation::{DEFAULT_OPERATION_LEAD, MAX_OPERATION_LEAD};

use super::*;

fn lead(sequence: u64, seconds: u64) -> AdministrativeRequest {
    let mut change = request(sequence);
    change.command = AdministrativeCommand::SetPolicyOperationLead(seconds);
    change
}

fn stores(vera: &VeraModule, acp: &AcpModule) -> (Vec<u8>, Vec<u8>) {
    (vera.store().serialize(), acp.store().serialize())
}

#[test]
fn the_lead_needs_a_quorum_and_the_next_sequence_and_survives_reopen() {
    let (policy, keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    vera.initialize_administration(policy).unwrap();
    assert_eq!(acp.policy_operation_lead().unwrap(), DEFAULT_OPERATION_LEAD);
    let approved = approve(lead(0, 86_400), &keys);
    let mut unauthorized = approved.clone();
    unauthorized.approvals.pop();
    let before = stores(&vera, &acp);
    for invalid in [unauthorized, approve(lead(1, 86_400), &keys)] {
        assert!(
            vera.apply_administrative_request(&mut acp, GENESIS, 100, &invalid)
                .is_err()
        );
        assert_eq!(stores(&vera, &acp), before);
    }
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &approved)
        .unwrap();
    assert_eq!(vera.administration().unwrap().unwrap().sequence, 1);
    assert!(
        vera.apply_administrative_request(&mut acp, GENESIS, 100, &approved)
            .is_err()
    );
    let reopened =
        AcpModule::from_store(InMemoryKvStore::deserialize(&acp.store().serialize()).unwrap());
    assert_eq!(reopened.policy_operation_lead().unwrap(), 86_400);
}

#[test]
fn a_lead_outside_its_bounds_is_refused_without_consuming_the_sequence() {
    let (policy, keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    vera.initialize_administration(policy).unwrap();
    for seconds in [0, DEFAULT_OPERATION_LEAD - 1, MAX_OPERATION_LEAD + 1] {
        let before = stores(&vera, &acp);
        assert!(
            vera.apply_administrative_request(
                &mut acp,
                GENESIS,
                100,
                &approve(lead(0, seconds), &keys)
            )
            .is_err()
        );
        assert_eq!(stores(&vera, &acp), before);
    }
    for (sequence, seconds) in [(0, MAX_OPERATION_LEAD), (1, DEFAULT_OPERATION_LEAD)] {
        vera.apply_administrative_request(
            &mut acp,
            GENESIS,
            100,
            &approve(lead(sequence, seconds), &keys),
        )
        .unwrap();
        assert_eq!(acp.policy_operation_lead().unwrap(), seconds);
    }
    assert_eq!(vera.administration().unwrap().unwrap().sequence, 2);
}

#[test]
fn the_lead_command_has_a_stable_json_spelling() {
    let command: AdministrativeCommand =
        serde_json::from_str(r#"{"SetPolicyOperationLead":86400}"#).unwrap();
    assert_eq!(
        command,
        AdministrativeCommand::SetPolicyOperationLead(86_400)
    );
}
