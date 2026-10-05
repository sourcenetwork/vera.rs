use super::*;

fn context(actor: &Did) -> (BlockExecCtx, TxExecCtx) {
    (
        BlockExecCtx {
            timestamp: Timestamp {
                seconds: 20,
                block_height: 2,
            },
            ..Default::default()
        },
        TxExecCtx {
            signer: actor.to_string(),
            tx_hash: vec![9; 32],
            sequence: 1,
        },
    )
}

#[test]
fn point_command_lifecycle_and_final_metadata_rewrite_are_atomic() {
    let (original, policy) = fixture();
    let owner = did("owner");
    let grant = record(&original, &policy).relationship;
    let (block, tx) = context(&owner);
    for command in [
        PolicyCmd::SetRelationship(grant.clone()),
        PolicyCmd::DeleteRelationship(grant.clone()),
        PolicyCmd::RegisterObject(Object {
            resource: "file".into(),
            id: "second".into(),
        }),
        PolicyCmd::TransferObject {
            object: object(),
            new_owner: Actor(owner.clone()),
        },
        PolicyCmd::TransferObject {
            object: object(),
            new_owner: Actor(did("next")),
        },
        PolicyCmd::UnarchiveObject(object()),
    ] {
        let mut start = original.clone();
        if matches!(command, PolicyCmd::DeleteRelationship(_)) {
            start
                .direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(grant.clone()))
                .unwrap();
        }
        let mut measured = start.clone();
        let budget = CommandBudget::new(u64::MAX);
        let result = measured
            .execute_policy_cmd_with_budget(&owner, &policy, command.clone(), &block, &tx, &budget)
            .unwrap();
        let mut exact = start.clone();
        let exact_budget = CommandBudget::new(budget.consumed());
        let actual = exact
            .execute_policy_cmd_with_budget(
                &owner,
                &policy,
                command.clone(),
                &block,
                &tx,
                &exact_budget,
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(result).unwrap()
        );
        assert_eq!(exact.store.serialize(), measured.store.serialize());
        exact.validate_restored_state().unwrap();
        let mut low = start.clone();
        let short = CommandBudget::new(budget.consumed() - 1);
        assert!(matches!(
            low.execute_policy_cmd_with_budget(&owner, &policy, command, &block, &tx, &short),
            Err(AcpError::CommandBudgetExceeded)
        ));
        assert_eq!(low.store.serialize(), start.store.serialize());
    }
    // Reactivation must pay for the owner rewrite too, not just the live retry above.
    let mut archived = original.clone();
    archived
        .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(object()))
        .unwrap();
    let before = archived.store.serialize();
    let mut measured = archived.clone();
    let budget = CommandBudget::new(u64::MAX);
    let result = measured
        .execute_policy_cmd_with_budget(
            &owner,
            &policy,
            PolicyCmd::UnarchiveObject(object()),
            &block,
            &tx,
            &budget,
        )
        .unwrap();
    assert!(matches!(
        result,
        PolicyCmdResult::UnarchiveObject {
            relationship_modified: true,
            ..
        }
    ));
    assert!(
        !measured
            .registration_owner_record(&policy, &object())
            .unwrap()
            .unwrap()
            .archived
    );
    assert!(matches!(
        archived.execute_policy_cmd_with_budget(
            &owner,
            &policy,
            PolicyCmd::UnarchiveObject(object()),
            &block,
            &tx,
            &CommandBudget::new(budget.consumed() - 1)
        ),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert_eq!(archived.store.serialize(), before);
    let request = types::PolicyCommandRequest {
        command: PolicyCmd::SetRelationship(grant),
        metadata: SuppliedMetadata {
            attributes: [("payload".into(), "x".repeat(60 << 10))].into(),
            ..Default::default()
        },
    };
    let mut measured = original.clone();
    let budget = CommandBudget::new(u64::MAX);
    let result = measured
        .execute_policy_cmd_with_metadata_and_budget(
            &owner,
            &policy,
            request.clone(),
            &block,
            &tx,
            &budget,
        )
        .unwrap();
    let cost = budget.consumed();
    let mut low = original.clone();
    assert!(matches!(
        low.execute_policy_cmd_with_metadata_and_budget(
            &owner,
            &policy,
            request.clone(),
            &block,
            &tx,
            &CommandBudget::new(cost - 1)
        ),
        Err(AcpError::CommandBudgetExceeded)
    ));
    assert_eq!(low.store.serialize(), original.store.serialize());
    let before = measured.store.serialize();
    let mut retry = request;
    retry.metadata = Default::default();
    let retry_budget = CommandBudget::new(u64::MAX);
    let PolicyCmdResult::SetRelationship {
        record: retried,
        record_existed,
    } = measured
        .execute_policy_cmd_with_metadata_and_budget(
            &owner,
            &policy,
            retry,
            &block,
            &tx,
            &retry_budget,
        )
        .unwrap()
    else {
        panic!("grant expected")
    };
    let PolicyCmdResult::SetRelationship { record, .. } = result else {
        panic!("grant expected")
    };
    assert!(record_existed);
    assert_eq!(retried.supplied_metadata, record.supplied_metadata);
    assert_eq!(measured.store.serialize(), before);
    assert!(retry_budget.consumed() > 60_000 / 16);
    assert!(retry_budget.consumed() < cost);
}

#[test]
fn reveal_amendment_and_context_are_rolled_back_on_the_final_reservation() {
    let (mut original, policy) = fixture();
    let next = did("next");
    let generated = original
        .query_generate_commitment(
            &policy,
            &[Object {
                resource: "file".into(),
                id: "new".into(),
            }],
            &Actor(next.clone()),
        )
        .unwrap();
    let (mut block, tx) = context(&next);
    block.timestamp.block_height = 1;
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = original
        .execute_policy_cmd(
            &next,
            &policy,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
            &block,
            &tx,
        )
        .unwrap()
    else {
        panic!("commitment expected")
    };
    // The same commitment first reveals a new object, then can amend a later owner's registration.
    for amendment in [false, true] {
        let mut start = original.clone();
        if amendment {
            let owner = did("owner");
            let (later, owner_tx) = context(&owner);
            start
                .execute_policy_cmd(
                    &owner,
                    &policy,
                    PolicyCmd::RegisterObject(generated.proofs[0].object.clone()),
                    &later,
                    &owner_tx,
                )
                .unwrap();
        }
        let command = PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        };
        let (later, tx) = context(&next);
        let mut measured = start.clone();
        let budget = CommandBudget::new(u64::MAX);
        let result = measured
            .execute_policy_cmd_with_budget(&next, &policy, command.clone(), &later, &tx, &budget)
            .unwrap();
        let PolicyCmdResult::RevealRegistration { record, event } = result else {
            panic!("reveal expected")
        };
        assert_eq!(event.is_some(), amendment);
        assert_eq!(record.metadata.creation_ts, block.timestamp);
        measured.validate_restored_state().unwrap();
        let mut exact = start.clone();
        exact
            .execute_policy_cmd_with_budget(
                &next,
                &policy,
                command.clone(),
                &later,
                &tx,
                &CommandBudget::new(budget.consumed()),
            )
            .unwrap();
        assert_eq!(exact.store.serialize(), measured.store.serialize());
        let mut low = start.clone();
        assert!(matches!(
            low.execute_policy_cmd_with_budget(
                &next,
                &policy,
                command,
                &later,
                &tx,
                &CommandBudget::new(budget.consumed() - 1)
            ),
            Err(AcpError::CommandBudgetExceeded)
        ));
        assert_eq!(low.store.serialize(), start.store.serialize());
    }
}

#[test]
fn archive_keeps_exact_bulk_semantics_and_only_meters_its_fixed_owner_rewrite() {
    let mut costs = Vec::new();
    for count in [1, 64] {
        let (mut module, policy) = fixture();
        let mut grant = record(&module, &policy);
        for i in 0..count {
            grant.relationship.subject = acp::Subject::entity(did(&format!("reader-{i}")));
            module.set_relationship(&grant).unwrap();
        }
        let original = module.clone();
        let budget = CommandBudget::new(u64::MAX);
        let result = module
            .direct_policy_cmd_with_budget(
                &did("owner"),
                &policy,
                PolicyCmd::ArchiveObject(object()),
                &budget,
            )
            .unwrap();
        assert!(
            matches!(result, PolicyCmdResult::ArchiveObject { found: true, relationships_removed } if relationships_removed == count + 1)
        );
        assert!(
            module
                .registration_owner_record(&policy, &object())
                .unwrap()
                .unwrap()
                .archived
        );
        module.validate_restored_state().unwrap();
        let mut short = original.clone();
        assert!(matches!(
            short.direct_policy_cmd_with_budget(
                &did("owner"),
                &policy,
                PolicyCmd::ArchiveObject(object()),
                &CommandBudget::new(budget.consumed() - 1)
            ),
            Err(AcpError::CommandBudgetExceeded)
        ));
        assert_eq!(short.store.serialize(), original.store.serialize());
        costs.push(budget.consumed());
    }
    assert_eq!(costs[0], costs[1]);
}
