//! Operator approval of the budget of long-lived operation outcomes.

use vera_modules::acp::operation::{DEFAULT_OPERATION_BYTES, OutcomeClass};

use super::*;

fn budget(sequence: u64, bytes: u64) -> AdministrativeRequest {
    let mut change = request(sequence);
    change.command = AdministrativeCommand::SetLongOperationBudget(bytes);
    change
}

fn stores(vera: &VeraModule, acp: &AcpModule) -> (Vec<u8>, Vec<u8>) {
    (vera.store().serialize(), acp.store().serialize())
}

#[test]
fn the_long_budget_needs_a_quorum_and_the_next_sequence_and_survives_reopen() {
    let (policy, keys) = operators();
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    vera.initialize_administration(policy).unwrap();
    assert_eq!(
        acp.long_operation_budget().unwrap(),
        DEFAULT_OPERATION_BYTES
    );
    let approved = approve(budget(0, 128 << 20), &keys);
    let mut unauthorized = approved.clone();
    unauthorized.approvals.pop();
    let before = stores(&vera, &acp);
    for invalid in [unauthorized, approve(budget(1, 128 << 20), &keys)] {
        assert!(
            vera.apply_administrative_request(&mut acp, GENESIS, 100, &invalid)
                .is_err()
        );
        assert_eq!(stores(&vera, &acp), before);
    }
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &approved)
        .unwrap();
    assert_eq!(vera.administration().unwrap().unwrap().sequence, 1);
    assert_eq!(acp.operation_budget().unwrap(), DEFAULT_OPERATION_BYTES);
    let reopened =
        AcpModule::from_store(InMemoryKvStore::deserialize(&acp.store().serialize()).unwrap());
    assert_eq!(reopened.long_operation_budget().unwrap(), 128 << 20);
}

#[test]
fn a_long_budget_below_the_record_limit_or_its_usage_is_refused_without_the_sequence() {
    let (policy, keys) = operators();
    let mut vera = VeraModule::new();
    let usage = 4u64 << 20;
    let mut acp = AcpModule::from_store(InMemoryKvStore::from_pairs(vec![(
        OutcomeClass::Long.bytes_key().to_vec(),
        usage.to_be_bytes().to_vec(),
    )]));
    vera.initialize_administration(policy).unwrap();
    for bytes in [0, usage - 1] {
        let before = stores(&vera, &acp);
        assert!(
            vera.apply_administrative_request(
                &mut acp,
                GENESIS,
                100,
                &approve(budget(0, bytes), &keys)
            )
            .is_err()
        );
        assert_eq!(stores(&vera, &acp), before);
    }
    vera.apply_administrative_request(&mut acp, GENESIS, 100, &approve(budget(0, usage), &keys))
        .unwrap();
    assert_eq!(acp.long_operation_budget().unwrap(), usage);
    let command: AdministrativeCommand =
        serde_json::from_str(r#"{"SetLongOperationBudget":268435456}"#).unwrap();
    assert_eq!(
        command,
        AdministrativeCommand::SetLongOperationBudget(256 << 20)
    );
}
