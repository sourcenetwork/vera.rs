use crate::acp::types::Operation;
use crate::acp::*;

fn fixture() -> (AcpModule, Did, String, AccessRequest) {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let policy = module
        .create_policy(
            &owner,
            "name: budget\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    let request = AccessRequest {
        actor: Actor(owner.clone()),
        operations: vec![Operation {
            object,
            permission: "owner".into(),
        }],
    };
    (module, owner, policy, request)
}

fn context(owner: &Did) -> (BlockExecCtx, TxExecCtx) {
    (
        BlockExecCtx {
            timestamp: Timestamp {
                seconds: 10,
                block_height: 1,
            },
            ..Default::default()
        },
        TxExecCtx {
            signer: owner.to_string(),
            tx_hash: vec![1; 32],
            sequence: 0,
        },
    )
}

#[test]
fn exact_query_allowance_and_shared_exhaustion_preserve_state() {
    let (module, _, policy, request) = fixture();
    let before = module.store.serialize();
    let measured = PermissionBudget::new(u64::MAX);
    assert!(
        module
            .query_verify_access_request_with_budget(&policy, &request, &measured)
            .unwrap()
    );
    let cost = measured.consumed();
    assert!(cost > 0);
    let exact = PermissionBudget::new(cost);
    assert!(
        module
            .query_verify_access_request_with_budget(&policy, &request, &exact)
            .unwrap()
    );
    assert_eq!(exact.consumed(), cost);
    assert!(!exact.is_exhausted());
    let shared = exact.clone();
    assert!(matches!(
        module.query_verify_access_request_with_budget(&policy, &request, &shared),
        Err(AcpError::PermissionBudgetExceeded)
    ));
    assert!(exact.is_exhausted());
    assert_eq!(exact.consumed(), cost);
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn final_decision_write_reservation_is_atomic_and_borsh_compatible() {
    let (original, owner, policy, request) = fixture();
    let (block, tx) = context(&owner);
    let mut measured = original.clone();
    let budget = PermissionBudget::new(u64::MAX);
    let decision = measured
        .check_access_with_budget(&owner, &policy, &request, &block, &tx, &budget)
        .unwrap();
    let expected = decision::DecisionRequest {
        deployment_id: block.deployment_id,
        policy_id: policy.clone(),
        creator: owner.to_string(),
        creator_sequence: tx.sequence,
        request: request.clone(),
    };
    let bytes = measured
        .store
        .get_ref(&keys::access_decision_key(&decision.id))
        .unwrap();
    assert_eq!(
        expected.verify_record(bytes, &block.timestamp).unwrap().id,
        decision.id
    );
    let required = budget.consumed();
    let mut exact = original.clone();
    let exact_budget = PermissionBudget::new(required);
    exact
        .check_access_with_budget(&owner, &policy, &request, &block, &tx, &exact_budget)
        .unwrap();
    assert_eq!(exact.store.serialize(), measured.store.serialize());
    assert_eq!(exact_budget.consumed(), required);
    let mut short = original.clone();
    let short_budget = PermissionBudget::new(required - 1);
    assert!(matches!(
        short.check_access_with_budget(&owner, &policy, &request, &block, &tx, &short_budget),
        Err(AcpError::PermissionBudgetExceeded)
    ));
    assert!(short_budget.is_exhausted());
    assert_eq!(short.store.serialize(), original.store.serialize());
    assert!(Arc::ptr_eq(
        &short.zanzibar_policies[&policy],
        &original.zanzibar_policies[&policy]
    ));
}

#[test]
fn corrupt_policy_is_charged_before_copying_or_decoding() {
    let (mut module, _, policy, request) = fixture();
    module
        .store
        .put(&keys::policy_key(&policy), vec![b'!'; 64 << 10]);
    let before = module.store.serialize();
    let short = PermissionBudget::new(1_000);
    assert!(matches!(
        module.query_verify_access_request_with_budget(&policy, &request, &short),
        Err(AcpError::PermissionBudgetExceeded)
    ));
    assert!(short.is_exhausted());
    let enough = PermissionBudget::new(u64::MAX);
    assert!(matches!(
        module.query_verify_access_request_with_budget(&policy, &request, &enough),
        Err(AcpError::State(_))
    ));
    assert!(enough.consumed() > short.consumed());
    assert!(!enough.is_exhausted());
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn permission_requests_share_work_and_retain_empty_query_semantics() {
    let (module, owner, policy, mut request) = fixture();
    let single = PermissionBudget::new(u64::MAX);
    assert!(
        module
            .query_verify_access_request_with_budget(&policy, &request, &single)
            .unwrap()
    );
    request.operations.push(request.operations[0].clone());
    let repeated = PermissionBudget::new(single.consumed());
    assert!(matches!(
        module.query_verify_access_request_with_budget(&policy, &request, &repeated),
        Err(AcpError::PermissionBudgetExceeded)
    ));
    assert!(repeated.is_exhausted());
    request.operations.resize(
        decision::MAX_ACCESS_OPERATIONS,
        request.operations[0].clone(),
    );
    assert!(
        module
            .query_verify_access_request(&policy, &request)
            .unwrap()
    );
    request.operations.push(request.operations[0].clone());
    let invalid = PermissionBudget::new(0);
    assert!(matches!(
        module.query_verify_access_request_with_budget(&policy, &request, &invalid),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    assert_eq!(invalid.consumed(), 0);
    assert!(!invalid.is_exhausted());
    request.operations.truncate(1);
    request.operations[0].object.id = "x".repeat((64 << 10) + 1);
    assert!(matches!(
        module.query_verify_access_request(&policy, &request),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    request.operations.clear();
    assert!(
        module
            .query_verify_access_request(&policy, &request)
            .unwrap()
    );
    assert!(matches!(
        module.query_verify_access_request("absent", &request),
        Err(AcpError::PolicyNotFound { .. })
    ));
    let (block, tx) = context(&owner);
    let mut module = module;
    let before = module.store.serialize();
    assert!(matches!(
        module.check_access(&owner, &policy, &request, &block, &tx),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn expression_work_is_charged_when_record_reads_are_identical() {
    use crate::acp::read_capture::{PERMISSION_READ_LIMITS, ReadCapture};

    let mut repeated = "reader".to_string();
    for _ in 0..5 {
        repeated = format!("({repeated} & {repeated})");
    }
    let definition = format!(
        "name: expression_budget\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: simple\n        expr: reader\n      - name: repeat\n        expr: '{repeated}'\n"
    );
    let owner = Did::new("did:key:owner").unwrap();
    let actor = Did::new("did:key:reader").unwrap();
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&owner, &definition, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "file",
                "report",
                "reader",
                actor.clone(),
            )),
        )
        .unwrap();
    let request = |permission: &str| AccessRequest {
        actor: Actor(actor.clone()),
        operations: vec![Operation {
            object: object.clone(),
            permission: permission.into(),
        }],
    };
    let simple = request("simple");
    let repeated = request("repeat");

    // Equal-length permission names and one shared policy keep request and policy
    // costs identical. Cached reader checks must not add record reads.
    let mut read_usage = Vec::new();
    for request in [&simple, &repeated] {
        let capture = ReadCapture::new(module.store.clone(), PERMISSION_READ_LIMITS);
        assert!(
            zanzibar_store::evaluate_access_request(capture.clone(), &policy, request).unwrap()
        );
        let remaining = capture.remaining_limits().unwrap();
        read_usage.push((
            capture.requests().unwrap(),
            remaining.reads,
            remaining.records,
            remaining.bytes,
        ));
    }
    assert_eq!(read_usage[0], read_usage[1]);
    let simple_budget = PermissionBudget::new(u64::MAX);
    assert!(
        module
            .query_verify_access_request_with_budget(&policy, &simple, &simple_budget)
            .unwrap()
    );
    let repeated_budget = PermissionBudget::new(u64::MAX);
    assert!(
        module
            .query_verify_access_request_with_budget(&policy, &repeated, &repeated_budget)
            .unwrap()
    );
    assert!(repeated_budget.consumed() > simple_budget.consumed());
    let read_equivalent_budget = PermissionBudget::new(simple_budget.consumed());
    assert!(matches!(
        module.query_verify_access_request_with_budget(&policy, &repeated, &read_equivalent_budget),
        Err(AcpError::PermissionBudgetExceeded)
    ));
    assert!(read_equivalent_budget.is_exhausted());
}
