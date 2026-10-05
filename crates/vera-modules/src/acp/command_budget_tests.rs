use super::*;
use crate::acp::*;

const POLICY: &str = "name: management\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n      - name: admin\n        types: [group->member]\n        manages: [reader, owner]\n      - name: backup\n        types: [actor]\n        manages: [reader]\n  - name: group\n    relations:\n      - name: member\n        types: [actor]\n";
fn did(name: &str) -> Did {
    Did::new(format!("did:key:{name}")).unwrap()
}
fn object() -> Object {
    Object {
        resource: "file".into(),
        id: "report".into(),
    }
}
fn grant() -> PolicyCmd {
    PolicyCmd::SetRelationship(Relationship::with_entity(
        "file",
        "report",
        "reader",
        did("reader"),
    ))
}
fn fixture() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let owner = did("owner");
    let policy = module
        .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    for object in [
        object(),
        Object {
            resource: "group".into(),
            id: "admins".into(),
        },
    ] {
        module
            .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object))
            .unwrap();
    }
    for rel in [
        Relationship::with_entity("group", "admins", "member", did("manager")),
        Relationship::new(
            "file",
            "report",
            "admin",
            acp::Subject::entity_set("group", "admins", "member"),
        ),
        Relationship::with_entity("file", "report", "backup", did("backup")),
    ] {
        module
            .direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(rel))
            .unwrap();
    }
    (module, policy)
}

#[test]
fn management_allowance_is_shared_across_userset_managers_and_preserves_denial() {
    let (module, policy) = fixture();
    let before = module.store.serialize();
    let mut costs = Vec::new();
    for (actor, allowed) in [
        ("owner", true),
        ("manager", true),
        ("backup", true),
        ("stranger", false),
    ] {
        let budget = CommandBudget::new(u64::MAX);
        assert_eq!(
            module
                .check_management_authority_with_budget(
                    &did(actor),
                    &policy,
                    &object(),
                    "reader",
                    &budget
                )
                .unwrap(),
            allowed
        );
        let cost = budget.consumed();
        costs.push(cost);
        let exact = CommandBudget::new(cost);
        assert_eq!(
            module
                .check_management_authority_with_budget(
                    &did(actor),
                    &policy,
                    &object(),
                    "reader",
                    &exact
                )
                .unwrap(),
            allowed
        );
        let short = CommandBudget::new(cost - 1);
        assert!(matches!(
            module.check_management_authority_with_budget(
                &did(actor),
                &policy,
                &object(),
                "reader",
                &short
            ),
            Err(AcpError::CommandBudgetExceeded)
        ));
        assert!(short.is_exhausted());
        assert_eq!(module.store.serialize(), before);
    }
    // Reaching later managers must pay for the preceding denied checks too.
    assert!(costs[1] > costs[0]);
    assert!(costs[2] > costs[1]);
    let first = CommandBudget::new(costs[0]);
    assert!(matches!(
        module.check_management_authority_with_budget(
            &did("backup"),
            &policy,
            &object(),
            "reader",
            &first
        ),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert!(matches!(
        module.check_management_authority_with_budget(
            &did("owner"),
            &policy,
            &object(),
            "reader",
            &first
        ),
        Err(AcpError::CommandBudgetExceeded)
    ));
}

#[test]
fn command_budget_covers_metadata_and_preserves_atomic_context() {
    let (original, policy) = fixture();
    let actor = did("manager");
    let block = BlockExecCtx {
        timestamp: Timestamp {
            seconds: 10,
            block_height: 1,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: actor.to_string(),
        tx_hash: vec![7; 32],
        sequence: 1,
    };
    let request = types::PolicyCommandRequest {
        command: grant(),
        metadata: SuppliedMetadata {
            attributes: [("note".into(), "x".repeat(60 << 10))].into(),
            ..Default::default()
        },
    };
    let mut measured = original.clone();
    let budget = CommandBudget::new(u64::MAX);
    let PolicyCmdResult::SetRelationship { record, .. } = measured
        .execute_policy_cmd_with_metadata_and_budget(
            &actor,
            &policy,
            request.clone(),
            &block,
            &tx,
            &budget,
        )
        .unwrap()
    else {
        panic!("grant expected")
    };
    assert_eq!(record.supplied_metadata, request.metadata);
    assert_eq!(record.metadata.creation_ts, block.timestamp);
    assert_eq!(record.metadata.tx_hash, tx.tx_hash);
    let mut exact = original.clone();
    exact
        .execute_policy_cmd_with_metadata_and_budget(
            &actor,
            &policy,
            request.clone(),
            &block,
            &tx,
            &CommandBudget::new(budget.consumed()),
        )
        .unwrap();
    assert_eq!(exact.store.serialize(), measured.store.serialize());
    let mut low = original.clone();
    let short = CommandBudget::new(budget.consumed() - 1);
    assert!(matches!(
        low.execute_policy_cmd_with_metadata_and_budget(
            &actor, &policy, request, &block, &tx, &short
        ),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert_eq!(low.store.serialize(), original.store.serialize());
    assert!(Arc::ptr_eq(
        &low.zanzibar_policies[&policy],
        &original.zanzibar_policies[&policy]
    ));
    let denied = CommandBudget::new(u64::MAX);
    assert!(matches!(
        low.execute_policy_cmd_with_budget(
            &did("stranger"),
            &policy,
            grant(),
            &block,
            &tx,
            &denied
        ),
        Err(AcpError::Unauthorized { .. })
    ));
    assert!(denied.consumed() > 0);
    assert_eq!(low.store.serialize(), original.store.serialize());
}

#[test]
fn management_rejects_unpaid_corrupt_policy_before_decode_and_preserves_actor_roles() {
    let (mut module, policy) = fixture();
    module
        .store
        .put(&keys::policy_key(&policy), vec![b'!'; 100 << 10]);
    let before = module.store.serialize();
    let budget = CommandBudget::new(100);
    assert!(matches!(
        module.check_management_authority_with_budget(
            &did("owner"),
            &policy,
            &object(),
            "reader",
            &budget
        ),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert!(matches!(
        module.check_management_authority_with_budget(
            &did("owner"),
            &policy,
            &object(),
            "reader",
            &CommandBudget::new(u64::MAX)
        ),
        Err(AcpError::State(_))
    ));
    assert_eq!(module.store.serialize(), before);
    let mut module = AcpModule::new();
    let policy = module.create_policy(&did("owner"), "name: roles\nactor:\n  relations:\n    - name: member\n      types: [actor]\nresources:\n  - name: file\n", PolicyMarshalingType::ShortYaml).unwrap().policy.id;
    let role = Object {
        resource: "actor".into(),
        id: "role".into(),
    };
    for (actor, allowed) in [("owner", true), ("stranger", false)] {
        let budget = CommandBudget::new(u64::MAX);
        assert_eq!(
            module
                .check_management_authority_with_budget(
                    &did(actor),
                    &policy,
                    &role,
                    "member",
                    &budget
                )
                .unwrap(),
            allowed
        );
        assert!(budget.consumed() > 0);
    }
}
