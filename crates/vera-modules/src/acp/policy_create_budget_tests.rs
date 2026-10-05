use super::*;
use crate::acp::types::PolicyCreation;

const POLICY: &str = "name: metered_creation\nresources:\n  - name: file\n";
fn context() -> (Did, BlockExecCtx, TxExecCtx) {
    let owner = Did::new("did:key:owner").unwrap();
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 10,
            block_height: 1,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: owner.to_string(),
        tx_hash: vec![1; 32],
        sequence: 0,
    };
    (owner, block, tx)
}
fn request() -> PolicyCreation {
    PolicyCreation {
        policy: POLICY.into(),
        marshal_type: PolicyMarshalingType::ShortYaml,
        required_specification: None,
        metadata: SuppliedMetadata {
            attributes: [("note".into(), "x".repeat(4096))].into(),
            ..Default::default()
        },
    }
}

#[test]
fn creation_exact_allowance_and_last_write_failure_preserve_id_allocation() {
    let (owner, block, tx) = context();
    let request = request();
    let original = AcpModule::new();
    let mut measured = original.clone();
    let budget = PolicyCreateBudget::new(u64::MAX);
    let record = measured
        .execute_create_policy_with_budget(&owner, &request, &block, &tx, &budget)
        .unwrap();
    let required = budget.consumed();
    assert!(required > 0);
    assert_eq!(record.supplied_metadata, request.metadata);
    assert_eq!(record.metadata.tx_signer, tx.signer);
    assert_eq!(record.metadata.creation_ts, block.timestamp);
    measured.validate_restored_state().unwrap();
    let mut exact = original.clone();
    let exact_budget = PolicyCreateBudget::new(required);
    assert_eq!(
        exact
            .execute_create_policy_with_budget(&owner, &request, &block, &tx, &exact_budget)
            .unwrap()
            .policy
            .id,
        record.policy.id
    );
    assert_eq!(exact.store.serialize(), measured.store.serialize());
    assert_eq!(exact_budget.consumed(), required);
    let mut short = original.clone();
    let short_budget = PolicyCreateBudget::new(required - 1);
    assert!(matches!(
        short.execute_create_policy_with_budget(&owner, &request, &block, &tx, &short_budget),
        Err(AcpError::PolicyCreateBudgetExceeded)
    ));
    assert!(short_budget.is_exhausted());
    assert_eq!(short.store.serialize(), original.store.serialize());
    assert!(short.zanzibar_policies.is_empty());
    assert_eq!(
        short
            .execute_create_policy(&owner, &request, &block, &tx)
            .unwrap()
            .policy
            .id,
        record.policy.id
    );
}

#[test]
fn creation_metadata_preserves_exact_encoded_limit_and_rejects_expansion() {
    let (owner, block, tx) = context();
    let mut request = request();
    request
        .metadata
        .attributes
        .insert("note".into(), String::new());
    let overhead = serde_json::to_vec(&request.metadata).unwrap().len();
    request
        .metadata
        .attributes
        .insert("note".into(), "x".repeat((64 << 10) - overhead));
    assert_eq!(
        serde_json::to_vec(&request.metadata).unwrap().len(),
        64 << 10
    );
    AcpModule::new()
        .execute_create_policy(&owner, &request, &block, &tx)
        .unwrap();
    for value in [
        format!("{}x", request.metadata.attributes["note"]),
        "\0".repeat(12_000),
    ] {
        request.metadata.attributes.insert("note".into(), value);
        let mut module = AcpModule::new();
        let before = module.store.serialize();
        let budget = PolicyCreateBudget::new(u64::MAX);
        assert!(matches!(
            module.execute_create_policy_with_budget(&owner, &request, &block, &tx, &budget),
            Err(AcpError::InvalidAccessRequest { .. })
        ));
        assert!(budget.consumed() > 0);
        assert_eq!(module.store.serialize(), before);
    }
}

#[test]
fn creation_charges_corrupt_counter_before_decoding_and_invalid_definition_work() {
    let (owner, _, _) = context();
    let mut module = AcpModule::new();
    module
        .store
        .put(keys::POLICY_COUNTER_KEY, vec![0; 64 << 10]);
    let before = module.store.serialize();
    let short = PolicyCreateBudget::new(1_000);
    assert!(matches!(
        module.create_policy_with_budget(&owner, POLICY, PolicyMarshalingType::ShortYaml, &short),
        Err(AcpError::PolicyCreateBudgetExceeded)
    ));
    assert!(short.is_exhausted());
    let enough = PolicyCreateBudget::new(u64::MAX);
    assert!(matches!(
        module.create_policy_with_budget(&owner, POLICY, PolicyMarshalingType::ShortYaml, &enough),
        Err(AcpError::State(_))
    ));
    assert!(enough.consumed() > short.consumed());
    assert_eq!(module.store.serialize(), before);
    let mut module = AcpModule::new();
    let before = module.store.serialize();
    let budget = PolicyCreateBudget::new(u64::MAX);
    assert!(matches!(
        module.create_policy_with_budget(
            &owner,
            "resources: [",
            PolicyMarshalingType::ShortYaml,
            &budget
        ),
        Err(AcpError::InvalidPolicy { .. })
    ));
    assert!(budget.consumed() > 0);
    assert_eq!(module.store.serialize(), before);
    assert!(module.zanzibar_policies.is_empty());
}
