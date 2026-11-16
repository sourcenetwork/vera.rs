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
        nonce: Default::default(),
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
            .id
            .to_string(),
        record.policy.id.to_string()
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
    assert!(short.policies.is_empty());
    assert_eq!(
        short
            .execute_create_policy(&owner, &request, &block, &tx)
            .unwrap()
            .policy
            .id
            .to_string(),
        record.policy.id.to_string()
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
fn creation_charges_invalid_definition_work() {
    let (owner, _, _) = context();
    let mut module = AcpModule::new();
    let before = module.store.serialize();
    let budget = PolicyCreateBudget::new(u64::MAX);
    assert!(matches!(
        module.create_policy_with_budget(
            &owner,
            "resources: [",
            PolicyMarshalingType::ShortYaml,
            Default::default(),
            &budget
        ),
        Err(AcpError::InvalidPolicy { .. })
    ));
    assert!(budget.consumed() > 0);
    assert_eq!(module.store.serialize(), before);
    assert!(module.policies.is_empty());
}

fn nonce(byte: u8) -> PolicyNonce {
    PolicyNonce([byte; 32])
}

#[test]
fn genesis_seeded_policies_match_predicted_ids() {
    let owner = Did::new("did:key:owner").unwrap();
    let other_policy = "name: second\nresources:\n  - name: widget\n";
    let yaml = PolicyMarshalingType::ShortYaml;
    let predicted_first =
        AcpModule::predict_policy_id(POLICY, &yaml, &nonce(1), owner.as_str()).unwrap();
    let predicted_second =
        AcpModule::predict_policy_id(other_policy, &yaml, &nonce(2), owner.as_str()).unwrap();
    let seed = |definition: &str, byte| PolicySeed {
        definition: definition.to_string(),
        marshal_type: yaml.clone(),
        nonce: nonce(byte),
    };

    let mut module = AcpModule::new();
    let records = module
        .initialize_policies(&owner, &[seed(POLICY, 1), seed(other_policy, 2)])
        .unwrap();
    assert_eq!(records[0].policy.id.as_str(), predicted_first);
    assert_eq!(records[1].policy.id.as_str(), predicted_second);
    assert_eq!(records[0].nonce, nonce(1));
    module.validate_restored_state().unwrap();

    // Seeding twice (e.g. a restarted genesis apply) is rejected.
    assert!(matches!(
        module.initialize_policies(&owner, &[seed(other_policy, 3)]),
        Err(AcpError::State(_))
    ));

    // Live creation of a seeded triple is refused and keeps the seed.
    let before = module.store.serialize();
    assert!(matches!(
        module.create_policy(&owner, POLICY, yaml.clone(), nonce(1)),
        Err(AcpError::PolicyAlreadyExists { id }) if id == predicted_first
    ));
    assert_eq!(module.store.serialize(), before);
    let live = module
        .create_policy(&owner, POLICY, yaml.clone(), nonce(9))
        .unwrap();
    assert_ne!(live.policy.id.as_str(), predicted_first);
}

#[test]
fn placed_policies_take_the_chosen_nonces_and_owners() {
    let other = "name: second\nresources:\n  - name: widget\n";
    let yaml = PolicyMarshalingType::ShortYaml;
    let placed = |definition: &str, byte, owner: &str| PlacedPolicy {
        definition: definition.to_string(),
        marshal_type: yaml.clone(),
        nonce: nonce(byte),
        owner: owner.to_string(),
    };

    let mut module = AcpModule::new();
    let records = module
        .initialize_placed_policies(&[
            placed(POLICY, 0, "did:key:first"),
            placed(POLICY, 0, "did:key:second"),
            placed(other, 0, "did:key:second"),
        ])
        .unwrap();
    for (record, (definition, owner)) in records.iter().zip([
        (POLICY, "did:key:first"),
        (POLICY, "did:key:second"),
        (other, "did:key:second"),
    ]) {
        assert_eq!(
            record.policy.id.to_string(),
            AcpModule::predict_policy_id(definition, &yaml, &nonce(0), owner).unwrap()
        );
        assert_eq!(record.metadata.owner_did, owner);
    }
    assert_ne!(
        records[0].policy.id, records[1].policy.id,
        "the owner is in the id"
    );

    let owner = Did::new("did:key:owner").unwrap();
    let live = module
        .create_policy(&owner, POLICY, yaml.clone(), nonce(3))
        .unwrap();
    assert_eq!(
        live.policy.id.to_string(),
        AcpModule::predict_policy_id(POLICY, &yaml, &nonce(3), owner.as_str()).unwrap()
    );
    module.validate_restored_state().unwrap();

    assert!(matches!(
        AcpModule::new().initialize_placed_policies(&[
            placed(POLICY, 3, "did:key:first"),
            placed(POLICY, 3, "did:key:first"),
        ]),
        Err(AcpError::PolicyAlreadyExists { .. })
    ));
    assert!(matches!(
        module.initialize_placed_policies(&[placed(other, 7, "did:key:first")]),
        Err(AcpError::State(_))
    ));
    assert!(matches!(
        AcpModule::new().initialize_placed_policies(&[placed(POLICY, 0, "not a did")]),
        Err(AcpError::State(_))
    ));
}

#[test]
fn every_spelling_of_a_key_gives_one_id() {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let spellings = [true, false].map(|compressed| {
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(key.verifying_key().to_encoded_point(compressed).as_bytes());
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    });
    let yaml = PolicyMarshalingType::ShortYaml;
    let ids: std::collections::BTreeSet<_> = spellings
        .iter()
        .map(|did| AcpModule::predict_policy_id(POLICY, &yaml, &nonce(0), did).unwrap())
        .collect();
    assert_eq!(ids.len(), 1);
    let mut module = AcpModule::new();
    let created = module
        .create_policy(
            &Did::new(&spellings[0]).unwrap(),
            POLICY,
            yaml.clone(),
            nonce(0),
        )
        .unwrap();
    assert!(ids.contains(created.policy.id.as_str()));
    assert!(matches!(
        module.create_policy(&Did::new(&spellings[1]).unwrap(), POLICY, yaml, nonce(0)),
        Err(AcpError::PolicyAlreadyExists { .. })
    ));
}
