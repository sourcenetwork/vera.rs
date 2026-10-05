use super::*;

const VALID: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n";
const UNDECLARED: &str = "name: files\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: missing\n";

#[test]
fn validation_and_execution_reject_undeclared_references() {
    let owner = Did::new("did:key:owner").unwrap();
    let mut module = AcpModule::new();
    assert!(
        !module
            .query_validate_policy(UNDECLARED, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .0
    );
    assert!(
        module
            .create_policy(&owner, UNDECLARED, PolicyMarshalingType::ShortYaml)
            .is_err()
    );
    let policy = module
        .create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let before = module.store.serialize();
    assert!(
        module
            .edit_policy(&owner, &policy, UNDECLARED, PolicyMarshalingType::ShortYaml)
            .is_err()
    );
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn failed_policy_construction_does_not_consume_a_counter() {
    let owner = Did::new("did:key:owner").unwrap();
    let mut module = AcpModule::new();
    let before = module.store.serialize();
    let invalid = VALID.replace("expr: reader", "expr: reader ^ writer");
    assert!(
        module
            .create_policy(&owner, &invalid, PolicyMarshalingType::ShortYaml)
            .is_err()
    );
    assert_eq!(module.store.serialize(), before);
    let expected = AcpModule::new()
        .create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml)
        .unwrap();
    assert_eq!(
        module
            .create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id,
        expected.policy.id
    );
}

#[test]
fn validation_respects_the_requested_format() {
    let module = AcpModule::new();
    for format in [
        PolicyMarshalingType::Unknown,
        PolicyMarshalingType::ShortJson,
    ] {
        assert!(!module.query_validate_policy(VALID, format).unwrap().0);
    }
}

#[test]
fn creation_rejects_invalid_counter_state_without_mutation() {
    let owner = Did::new("did:key:owner").unwrap();
    for counter in [
        Vec::new(),
        vec![0; 7],
        vec![0; 9],
        u64::MAX.to_be_bytes().to_vec(),
    ] {
        let mut module = AcpModule::new();
        module.store.put(keys::POLICY_COUNTER_KEY, counter);
        let before = module.store.serialize();
        assert!(matches!(
            module.create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml),
            Err(AcpError::State(_))
        ));
        assert_eq!(module.store.serialize(), before);
        assert!(module.zanzibar_policies.is_empty());
    }
}

#[test]
fn json_policy_uses_shared_semantics_for_creation_and_editing() {
    let json = r#"{"name":"files","resources":[{"name":"file","relations":[{"name":"reader"}],"permissions":[{"name":"read","expr":"reader"}]}]}"#;
    let yaml_policy =
        AcpModule::validate_policy_definition(VALID, PolicyMarshalingType::ShortYaml).unwrap();
    let json_policy =
        AcpModule::validate_policy_definition(json, PolicyMarshalingType::ShortJson).unwrap();
    assert_eq!(
        serde_json::to_value(yaml_policy).unwrap(),
        serde_json::to_value(json_policy).unwrap()
    );
    let owner = Did::new("did:key:owner").unwrap();
    let mut module = AcpModule::new();
    let record = module
        .create_policy(&owner, json, PolicyMarshalingType::ShortJson)
        .unwrap();
    assert_eq!(record.marshal_type, PolicyMarshalingType::ShortJson);
    let id = record.policy.id;
    module
        .edit_policy(
            &owner,
            &id,
            &json.replace("reader", "editor"),
            PolicyMarshalingType::ShortJson,
        )
        .unwrap();
    let before = module.store.serialize();
    for invalid in [
        json.replace("\"expr\":\"reader\"", "\"expr\":\"missing\""),
        json.replace(
            "\"name\":\"files\"",
            "\"name\":\"files\",\"name\":\"duplicate\"",
        ),
        format!("{json} trailing"),
        format!("{}{}", " ".repeat(64 * 1024), json),
    ] {
        assert!(
            module
                .edit_policy(&owner, &id, &invalid, PolicyMarshalingType::ShortJson)
                .is_err()
        );
        assert_eq!(module.store.serialize(), before);
    }
    let restored = AcpModule::from_store(InMemoryKvStore::deserialize(&before).unwrap());
    restored.validate_restored_state().unwrap();
    assert_eq!(
        restored.query_policy(&id).unwrap().marshal_type,
        PolicyMarshalingType::ShortJson
    );
}

#[test]
fn policy_id_listing_is_bounded_and_rejects_invalid_keys() {
    let mut module = AcpModule::new();
    let mut record = module
        .create_policy(
            &Did::new("did:key:owner").unwrap(),
            VALID,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    module.store.delete(&keys::policy_key(&record.policy.id));
    for n in 0..128u64 {
        record.policy.id = format!("{n:064x}");
        module.set_policy_record(&record.policy.id, &record);
    }
    let ids = module.query_policy_ids().unwrap();
    assert_eq!(ids.len(), 128);
    assert_eq!(ids.first().unwrap(), &format!("{:064x}", 0));
    assert_eq!(ids.last().unwrap(), &format!("{:064x}", 127));
    module
        .store
        .put(&keys::policy_key(&format!("{:064x}", 128)), Vec::new());
    assert!(matches!(
        module.query_policy_ids(),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    for suffix in [vec![255], b"short".to_vec(), vec![b'A'; 64]] {
        let mut module = AcpModule::new();
        let mut key = keys::POLICY_PREFIX.to_vec();
        key.extend(suffix);
        module.store.put(&key, Vec::new());
        assert!(matches!(module.query_policy_ids(), Err(AcpError::State(_))));
    }
}

#[test]
fn policy_id_listing_rejects_corrupt_records_after_restore() {
    let mut module = AcpModule::new();
    let record = module
        .create_policy(
            &Did::new("did:key:owner").unwrap(),
            VALID,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    let id = record.policy.id.clone();
    let valid = serde_json::to_vec(&record).unwrap();
    let mut foreign = record;
    foreign.policy.id = "ab".repeat(32);
    for invalid in [
        valid[..valid.len() - 1].to_vec(),
        serde_json::to_vec(&foreign).unwrap(),
    ] {
        module.store.put(&keys::policy_key(&id), invalid);
        let before = module.store.serialize();
        for candidate in [
            module.clone(),
            AcpModule::from_store(InMemoryKvStore::deserialize(&before).unwrap()),
        ] {
            assert!(matches!(
                candidate.query_policy_ids(),
                Err(AcpError::State(_))
            ));
            assert!(matches!(
                candidate.query_policy(&id),
                Err(AcpError::State(_))
            ));
            assert_eq!(candidate.store.serialize(), before);
        }
    }
    module.store.put(&keys::policy_key(&id), valid);
    assert_eq!(module.query_policy_ids().unwrap(), vec![id]);
}

fn exact_byte_listing() -> AcpModule {
    let mut module = AcpModule::new();
    let mut record = module
        .create_policy(
            &Did::new("did:key:owner").unwrap(),
            VALID,
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    module.store.delete(&keys::policy_key(&record.policy.id));
    for n in 0..2 {
        record.policy.id = format!("{n:064x}");
        let key = keys::policy_key(&record.policy.id);
        let mut value = serde_json::to_vec(&record).unwrap();
        // Valid JSON whitespace makes the exact stored-byte boundary independent of schema size.
        value.resize((1 << 19) - key.len(), b' ');
        module.store.put(&key, value);
    }
    module
}

#[test]
fn policy_id_listing_accepts_exact_byte_and_work_limits_and_rejects_one_more() {
    let mut module = exact_byte_listing();
    let before = module.store.serialize();
    let mut measured = PolicyListBudget::new(u64::MAX);
    let ids = module.query_policy_ids_with_budget(&mut measured).unwrap();
    assert_eq!(ids, vec![format!("{:064x}", 0), format!("{:064x}", 1)]);
    assert_eq!(measured.consumed(), 2 * (100 + (1 << 19) / 16));
    let mut exact = PolicyListBudget::new(measured.consumed());
    assert_eq!(
        module.query_policy_ids_with_budget(&mut exact).unwrap(),
        ids
    );
    assert!(!exact.is_exhausted());
    let mut short = PolicyListBudget::new(measured.consumed() - 1);
    assert!(matches!(
        module.query_policy_ids_with_budget(&mut short),
        Err(AcpError::PolicyListBudgetExceeded)
    ));
    assert!(short.is_exhausted());
    assert_eq!(short.consumed(), measured.consumed() / 2);
    assert_eq!(module.store.serialize(), before);

    let key = keys::policy_key(&ids[1]);
    let mut value = module.store.get(&key).unwrap();
    value.push(b' ');
    module.store.put(&key, value);
    let over = module.store.serialize();
    let mut budget = PolicyListBudget::new(u64::MAX);
    assert!(matches!(
        module.query_policy_ids_with_budget(&mut budget),
        Err(AcpError::InvalidAccessRequest { reason }) if reason.contains("use certified prefix pages")
    ));
    assert_eq!(budget.consumed(), measured.consumed() + 1);
    assert!(!budget.is_exhausted());
    assert_eq!(module.store.serialize(), over);
    let first = module.query_policies_page(None).unwrap();
    assert_eq!(first.records.len(), 1);
    let next = module.query_policies_page(first.next.as_deref()).unwrap();
    assert_eq!(next.records.len(), 1);
    assert!(next.next.is_none());
}

#[test]
fn policy_id_listing_preflights_all_bytes_before_decoding_and_preserves_corruption_errors() {
    let mut module = exact_byte_listing();
    let first = keys::policy_key(&format!("{:064x}", 0));
    let second = keys::policy_key(&format!("{:064x}", 1));
    let mut corrupt = module.store.get(&first).unwrap();
    corrupt[0] = b'!';
    module.store.put(&first, corrupt);
    let mut value = module.store.get(&second).unwrap();
    value.push(b' ');
    module.store.put(&second, value.clone());
    let before = module.store.serialize();
    let mut over = PolicyListBudget::new(u64::MAX);
    assert!(matches!(
        module.query_policy_ids_with_budget(&mut over),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    assert!(over.consumed() > 0);
    assert_eq!(module.store.serialize(), before);

    value.pop();
    module.store.put(&second, value);
    let before = module.store.serialize();
    let mut charged = PolicyListBudget::new(u64::MAX);
    assert!(matches!(
        module.query_policy_ids_with_budget(&mut charged),
        Err(AcpError::State(_))
    ));
    assert!(charged.consumed() > 0);
    assert!(!charged.is_exhausted());
    let mut exhausted = PolicyListBudget::new(0);
    assert!(matches!(
        module.query_policy_ids_with_budget(&mut exhausted),
        Err(AcpError::PolicyListBudgetExceeded)
    ));
    assert!(exhausted.is_exhausted());
    assert_eq!(exhausted.consumed(), 0);
    assert_eq!(module.store.serialize(), before);
    // Reusing the exhausted allowance cannot succeed even after a snapshot change.
    assert!(matches!(
        AcpModule::new().query_policy_ids_with_budget(&mut exhausted),
        Err(AcpError::PolicyListBudgetExceeded)
    ));
}
