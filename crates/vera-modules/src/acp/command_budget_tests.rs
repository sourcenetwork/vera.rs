use super::*;
use crate::acp::*;

const POLICY: &str = "name: management\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n      - name: admin\n        types: [group->member]\n        manages: [reader]\n      - name: backup\n        types: [actor]\n        manages: [reader]\n  - name: group\n    relations:\n      - name: member\n        types: [actor]\n";
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
    PolicyCmd::SetRelationship(
        crate::acp::relationship_values::actor_relationship(
            "file",
            "report",
            "reader",
            &did("reader"),
        )
        .unwrap(),
    )
}
fn fixture() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let owner = did("owner");
    let policy = module
        .create_policy(
            &owner,
            POLICY,
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string();
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
        crate::acp::relationship_values::actor_relationship(
            "group",
            "admins",
            "member",
            &did("manager"),
        )
        .unwrap(),
        crate::acp::relationship_values::relationship(
            "file",
            "report",
            "admin",
            crate::acp::relationship_values::actor_set("group", "admins", "member"),
        ),
        crate::acp::relationship_values::actor_relationship(
            "file",
            "report",
            "backup",
            &did("backup"),
        )
        .unwrap(),
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
    // One union of every manager is checked: no manager is reached for free.
    assert!(costs.iter().all(|cost| *cost > 0));
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
        &low.policies[&policy],
        &original.policies[&policy]
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
fn management_rejects_unpaid_corrupt_policy_before_decode_and_actor_relations() {
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
    let (module, policy) = fixture();
    let role = Object {
        resource: "actor".into(),
        id: "role".into(),
    };
    assert!(matches!(
        module.check_management_authority_with_budget(
            &did("owner"),
            &policy,
            &role,
            "member",
            &CommandBudget::new(u64::MAX)
        ),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
}

#[test]
fn a_command_without_supplied_metadata_writes_its_record_once() {
    let (original, policy) = fixture();
    let actor = did("owner");
    let block = BlockExecCtx {
        timestamp: crate::types::Timestamp {
            block_height: 9,
            seconds: 90,
        },
        ..Default::default()
    };
    let tx = TxExecCtx {
        signer: actor.to_string(),
        tx_hash: vec![7; 32],
        sequence: 1,
    };
    let plain = CommandBudget::new(u64::MAX);
    let mut contextual = original.clone();
    contextual
        .execute_policy_cmd_with_budget(&actor, &policy, grant(), &block, &tx, &plain)
        .unwrap();
    let with_metadata = CommandBudget::new(u64::MAX);
    let mut supplied = original;
    supplied
        .execute_policy_cmd_with_metadata_and_budget(
            &actor,
            &policy,
            types::PolicyCommandRequest {
                command: grant(),
                metadata: SuppliedMetadata::default(),
            },
            &block,
            &tx,
            &with_metadata,
        )
        .unwrap();
    assert_eq!(supplied.store.serialize(), contextual.store.serialize());
    let input = CommandBudget::new(u64::MAX);
    input.metadata(&SuppliedMetadata::default()).unwrap();
    assert_eq!(
        with_metadata.consumed(),
        plain.consumed() + input.consumed()
    );
}
