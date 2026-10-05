use crate::acp::*;

const ORIGINAL: &str =
    "name: bounded_edit\nresources:\n  - name: file\n    relations:\n      - name: reader\n";
const REPLACEMENT: &str = "name: bounded_edit\nresources:\n  - name: file\n";

fn revision() -> Timestamp {
    Timestamp {
        block_height: 1,
        seconds: 10,
    }
}

fn fixture(grants: usize) -> (AcpModule, Did, String) {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let policy = module
        .create_policy(&owner, ORIGINAL, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::RegisterObject(Object {
                resource: "file".into(),
                id: "report".into(),
            }),
        )
        .unwrap();
    for index in 0..grants {
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::SetRelationship(Relationship::with_entity(
                    "file",
                    "report",
                    "reader",
                    Did::new(format!("did:key:reader{index}")).unwrap(),
                )),
            )
            .unwrap();
    }
    (module, owner, policy)
}

fn edit(
    module: &mut AcpModule,
    actor: &Did,
    policy: &str,
    at: &Timestamp,
    budget: &PolicyEditBudget,
) -> Result<(u64, PolicyRecord)> {
    module.edit_policy_at_with_budget(
        actor,
        policy,
        REPLACEMENT,
        PolicyMarshalingType::ShortYaml,
        at,
        budget,
    )
}

fn assert_unchanged(module: &AcpModule, before: &AcpModule, policy: &str) {
    assert_eq!(module.store.serialize(), before.store.serialize());
    assert!(Arc::ptr_eq(
        &module.zanzibar_policies[policy],
        &before.zanzibar_policies[policy]
    ));
    assert!(
        module.zanzibar_policies[policy]
            .get_relation("file", "reader")
            .is_some()
    );
}

#[test]
fn exact_edit_budget_succeeds_and_one_less_preserves_state_and_cache() {
    let (original, owner, policy) = fixture(32);
    let mut measured = original.clone();
    let unlimited = PolicyEditBudget::new(u64::MAX);
    assert_eq!(
        edit(&mut measured, &owner, &policy, &revision(), &unlimited)
            .unwrap()
            .0,
        32
    );
    let required = unlimited.consumed();
    assert!(required > 1);
    assert!(!unlimited.is_exhausted());

    let mut exact = original.clone();
    let budget = PolicyEditBudget::new(required);
    let (removed, record) = edit(&mut exact, &owner, &policy, &revision(), &budget).unwrap();
    assert_eq!(removed, 32);
    assert_eq!(record.last_modified, Some(revision()));
    assert_eq!(budget.consumed(), required);
    assert!(!budget.is_exhausted());
    assert_eq!(exact.store.serialize(), measured.store.serialize());
    assert!(
        exact.zanzibar_policies[&policy]
            .get_relation("file", "reader")
            .is_none()
    );
    exact.validate_restored_state().unwrap();

    let mut short = original.clone();
    let budget = PolicyEditBudget::new(required - 1);
    assert!(edit(&mut short, &owner, &policy, &revision(), &budget).is_err());
    assert!(budget.is_exhausted());
    assert!(budget.consumed() > 0);
    assert_unchanged(&short, &original, &policy);
}

#[test]
fn oversized_corrupt_policy_exhausts_read_budget_before_decoding() {
    let (mut module, owner, policy) = fixture(0);
    let outsider = Did::new("did:key:outsider").unwrap();
    let ordinary = PolicyEditBudget::new(u64::MAX);
    assert!(matches!(
        edit(&mut module, &outsider, &policy, &revision(), &ordinary),
        Err(AcpError::Unauthorized { .. })
    ));
    assert!(ordinary.consumed() > 0);
    module.store.put(
        &keys::policy_key(&policy),
        vec![b'!'; crate::kv_store::NATIVE_MAX_VALUE_BYTES + 1],
    );
    let before = module.clone();
    let budget = PolicyEditBudget::new(ordinary.consumed());
    assert!(edit(&mut module, &owner, &policy, &revision(), &budget).is_err());
    assert!(
        budget.is_exhausted(),
        "malformed JSON must not be decoded before charging its bytes"
    );
    assert_unchanged(&module, &before, &policy);
}

#[test]
fn edit_work_depends_on_pair_indexes_not_physical_grant_count() {
    let mut costs = Vec::new();
    for grants in [32, 256] {
        let (mut module, owner, policy) = fixture(grants);
        let physical = module
            .store
            .prefix_scan(&keys::relationship_policy_prefix(&policy));
        assert_eq!(physical.len(), grants + 1);
        let budget = PolicyEditBudget::new(u64::MAX);
        assert_eq!(
            edit(&mut module, &owner, &policy, &revision(), &budget)
                .unwrap()
                .0,
            grants as u64
        );
        assert!(!budget.is_exhausted());
        assert_eq!(
            module
                .store
                .prefix_scan(&keys::relationship_policy_prefix(&policy)),
            physical
        );
        let current = module
            .query_filter_relationships(&policy, &Default::default())
            .unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].relationship.relation, "owner");
        module.validate_restored_state().unwrap();
        costs.push(budget.consumed());
    }
    assert!(costs[0] > 0);
    assert_eq!(costs[0], costs[1]);
}

#[test]
fn rejected_owner_and_revision_checks_charge_reads_without_mutation() {
    let (original, owner, policy) = fixture(1);
    for unauthorized in [false, true] {
        let mut module = original.clone();
        let outsider = Did::new("did:key:outsider").unwrap();
        let actor = if unauthorized { &outsider } else { &owner };
        let at = if unauthorized {
            revision()
        } else {
            Timestamp::default()
        };
        let budget = PolicyEditBudget::new(u64::MAX);
        let error = edit(&mut module, actor, &policy, &at, &budget).unwrap_err();
        if unauthorized {
            assert!(matches!(error, AcpError::Unauthorized { .. }));
        } else {
            assert!(matches!(error, AcpError::InvalidAccessRequest { .. }));
        }
        assert!(budget.consumed() > 0);
        assert!(!budget.is_exhausted());
        assert_unchanged(&module, &original, &policy);
    }
}

#[test]
fn budgeted_edit_counts_target_and_userset_invalidation_once() {
    let definition = "name: overlap\nresources:\n  - name: file\n    relations:\n      - name: reader\n      - name: writer\n  - name: group\n    relations:\n      - name: member\n";
    let replacement = "name: overlap\nresources:\n  - name: file\n    relations:\n      - name: writer\n  - name: group\n";
    let owner = Did::new("did:key:owner").unwrap();
    let reader = Did::new("did:key:reader").unwrap();
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&owner, definition, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    for (resource, id) in [("file", "report"), ("group", "staff")] {
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: resource.into(),
                    id: id.into(),
                }),
            )
            .unwrap();
    }
    for relationship in [
        Relationship::with_entity("group", "staff", "member", reader.clone()),
        Relationship::new(
            "file",
            "report",
            "reader",
            acp::Subject::entity_set("group", "staff", "member"),
        ),
        Relationship::new(
            "file",
            "report",
            "writer",
            acp::Subject::entity_set("group", "staff", "member"),
        ),
        Relationship::with_entity("file", "report", "reader", reader.clone()),
        Relationship::with_entity("file", "report", "writer", reader),
    ] {
        module
            .direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(relationship))
            .unwrap();
    }
    let physical = module
        .store
        .prefix_scan(&keys::relationship_policy_prefix(&policy));
    assert_eq!(physical.len(), 7);
    let budget = PolicyEditBudget::new(u64::MAX);
    let (removed, _) = module
        .edit_policy_at_with_budget(
            &owner,
            &policy,
            replacement,
            PolicyMarshalingType::ShortYaml,
            &revision(),
            &budget,
        )
        .unwrap();
    assert_eq!(removed, 4);
    assert!(budget.consumed() > 0);
    assert!(!budget.is_exhausted());
    assert_eq!(
        module
            .store
            .prefix_scan(&keys::relationship_policy_prefix(&policy)),
        physical
    );
    let current = module
        .query_filter_relationships(&policy, &Default::default())
        .unwrap();
    assert_eq!(current.len(), 3);
    assert_eq!(
        current
            .iter()
            .filter(|record| record.relationship.relation == "owner")
            .count(),
        2
    );
    assert_eq!(
        current
            .iter()
            .filter(|record| record.relationship.relation == "writer")
            .count(),
        1
    );
    module.validate_restored_state().unwrap();
}

#[test]
fn bearer_definition_bounds_and_work_are_checked_before_digest_or_authorization() {
    let mut module = AcpModule::new();
    let mut vera = crate::vera::VeraModule::new();
    let block = crate::types::BlockExecCtx::default();
    let submission = crate::types::TxExecCtx {
        signer: "did:key:worker".into(),
        tx_hash: vec![1; 32],
        sequence: 0,
    };
    for (definition, oversized) in [
        ("x".to_string(), false),
        ("x".repeat(MAX_POLICY_DEFINITION_BYTES + 1), true),
    ] {
        let budget = PolicyEditBudget::new(0);
        let error = module
            .bearer_edit_policy_with_budget(
                &mut vera,
                &block,
                &submission,
                "invalid-token",
                "missing-policy",
                &definition,
                PolicyMarshalingType::ShortYaml,
                &budget,
            )
            .unwrap_err();
        if oversized {
            assert!(matches!(error, AcpError::InvalidPolicy { .. }));
            assert!(!budget.is_exhausted());
        } else {
            assert!(matches!(error, AcpError::PolicyEditBudgetExceeded));
            assert!(budget.is_exhausted());
        }
        assert_eq!(module.store().prefix_iter(b"").count(), 0);
        assert_eq!(vera.store().prefix_iter(b"").count(), 0);
    }
}
